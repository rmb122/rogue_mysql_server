package main

import (
    "rogue_mysql_server/mysql"
    "vitess.io/vitess/go/sqltypes"
    "vitess.io/vitess/go/vt/proto/query"
)

type Column struct {
    // Name is the name of the column.
    Name string
    // Type is the data type of the column.
    Type query.Type
    // Default contains the default value of the column or nil if it is NULL.
    Default interface{}
    // Nullable is true if the column can contain NULL values, or false
    // otherwise.
    Nullable bool
    // Source is the name of the table this column came from.
    Source string
    // PrimaryKey is true if the column is part of the primary key for its table.
    PrimaryKey bool
}

type Schema []*Column
type Row []interface{}

func schemaToFields(s Schema) []*query.Field {
    fields := make([]*query.Field, len(s))
    for i, c := range s {
        var charset uint32 = mysql.CharacterSetUtf8
        if c.Type == sqltypes.Blob {
            charset = mysql.CharacterSetBinary
        }

        fields[i] = &query.Field{
            Name:    c.Name,
            Type:    c.Type,
            Charset: charset,
        }
    }
    return fields
}

func rowToSQL(row Row) []sqltypes.Value {
    o := make([]sqltypes.Value, len(row))

    for i, v := range row {
        switch value := v.(type) {
        case []byte:
            o[i] = sqltypes.MakeTrusted(sqltypes.Blob, value)
            break
        case string:
            o[i] = sqltypes.MakeTrusted(sqltypes.Text, []byte(value))
        default:
            o[i] = sqltypes.MakeTrusted(sqltypes.Blob, []byte{})
            break
        }
    }

    return o
}

func getMysqlVars() *sqltypes.Result {
    r := &sqltypes.Result{Fields: schemaToFields(Schema{
        {Name: "system_time_zone", Type: sqltypes.Text, Nullable: false},
        {Name: "time_zone", Type: sqltypes.Text, Nullable: false},
        {Name: "init_connect", Type: sqltypes.Text, Nullable: false},
        {Name: "auto_increment_increment", Type: sqltypes.Text, Nullable: false},
        {Name: "max_allowed_packet", Type: sqltypes.Text, Nullable: false},
    })}
    r.Rows = append(r.Rows, rowToSQL(Row{"UTC", "SYSTEM", "", "1", "10000"}))
    return r
}