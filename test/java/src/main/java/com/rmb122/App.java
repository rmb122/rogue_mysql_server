package com.rmb122;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws Exception {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/?allowLoadLocalInfile=true", "root", "root");
        Statement stmt = connection.createStatement();
        stmt.executeQuery("SELECT 1;");
    }
}
