package mysql

import (
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
type SQLRow []interface{}

func SchemaToFields(s Schema) []*query.Field {
    fields := make([]*query.Field, len(s))
    for i, c := range s {
        var charset uint32 = CharacterSetUtf8
        if c.Type == sqltypes.Blob {
            charset = CharacterSetBinary
        }

        fields[i] = &query.Field{
            Name:    c.Name,
            Type:    c.Type,
            Charset: charset,
        }
    }
    return fields
}

func RowToSQL(row SQLRow) []sqltypes.Value {
    o := make([]sqltypes.Value, len(row))

    for i, v := range row {
        switch value := v.(type) {
        case []byte:
            o[i] = sqltypes.MakeTrusted(sqltypes.Blob, value)
        case string:
            o[i] = sqltypes.MakeTrusted(sqltypes.Text, []byte(value))
        default:
            o[i] = sqltypes.MakeTrusted(sqltypes.Blob, []byte{})
        }
    }

    return o
}

func GetMysqlVars() *sqltypes.Result {
    r := &sqltypes.Result{Fields: SchemaToFields(Schema{
        {Name: "system_time_zone", Type: sqltypes.Text, Nullable: false},
        {Name: "time_zone", Type: sqltypes.Text, Nullable: false},
        {Name: "init_connect", Type: sqltypes.Text, Nullable: false},
        {Name: "auto_increment_increment", Type: sqltypes.Text, Nullable: false},
        {Name: "max_allowed_packet", Type: sqltypes.Text, Nullable: false},
    })}
    r.Rows = append(r.Rows, RowToSQL(SQLRow{"UTC", "SYSTEM", "", "1", "10000"}))
    return r
}