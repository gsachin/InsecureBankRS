package com.security.insecurebankrs;

import java.util.HashMap;
import android.content.ContentProvider;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteQueryBuilder;
import android.net.Uri;

/* The class that keeps a track of all the logged in users' on the device
   @author Dinesh Shetty
*/

public class TrackUserContentProvider extends ContentProvider {
    //   This content provider vuln is a modified code from www.androidpentesting.com

    // VULNERABILITY: Using a static final String for PROVIDER_NAME can expose sensitive information.
    // OWASP Reference: https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure
    /*
    static final String PROVIDER_NAME = "com.security.insecurebankrs.TrackUserContentProvider";
    static final String URL = "content://" + PROVIDER_NAME + "/trackerusers";
    static final Uri CONTENT_URI = Uri.parse(URL);
    */
    static final String PROVIDER_NAME = "com.security.insecurebankrs.TrackUserContentProvider";
    static final String URL = "content://" + PROVIDER_NAME + "/trackerusers";
    static final Uri CONTENT_URI = Uri.parse(URL);

    static final String name = "name";
    static final int uriCode = 1;
    static final UriMatcher uriMatcher;
    private static HashMap<String, String> values;
    private SQLiteDatabase db;

    static final String DATABASE_NAME = "mydb";
    static final String TABLE_NAME = "names";
    static final int DATABASE_VERSION = 1;

    // VULNERABILITY: SQL Injection risk if table/column names are user-controlled.
    // OWASP Reference: https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
    /*
    static final String CREATE_DB_TABLE = " CREATE TABLE " + TABLE_NAME + " (id INTEGER PRIMARY KEY AUTOINCREMENT, " + " name TEXT NOT NULL);";
    */
    static final String CREATE_DB_TABLE = "CREATE TABLE " + TABLE_NAME + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL);";

    static {
        // VULNERABILITY: URIMatcher setup without proper security checks.
        // OWASP Reference: https://owasp.org/www-project-mobile-top-ten/2016-risks/m7-client-code-quality
        /*
        uriMatcher = new UriMatcher(UriMatcher.NO_MATCH);
        uriMatcher.addURI(PROVIDER_NAME, "trackerusers", uriCode);
        uriMatcher.addURI(PROVIDER_NAME, "trackerusers/*", uriCode);
        */
        uriMatcher = new UriMatcher(UriMatcher.NO_MATCH);
        uriMatcher.addURI(PROVIDER_NAME, "trackerusers", uriCode);
        uriMatcher.addURI(PROVIDER_NAME, "trackerusers/*", uriCode);
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // VULNERABILITY: Lack of proper input validation and potential SQL Injection in delete method.
        // OWASP Reference: https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
        /*
        int count = db.delete(TABLE_NAME, selection, selectionArgs);
        */
        int count = db.delete(TABLE_NAME, sanitizeInput(selection), selectionArgs);
        getContext().getContentResolver().notifyChange(uri, null);
        return count;
    }

    @Override
    public String getType(Uri uri) {
        // VULNERABILITY: getType method might expose internal implementation details.
        // OWASP Reference: https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration
        switch (uriMatcher.match(uri)) {
            case uriCode:
                return "vnd.android.cursor.dir/u";
            default:
                throw new IllegalArgumentException("Unsupported URI: " + uri);
        }
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // VULNERABILITY: No validation of input values, which could lead to SQL Injection.
        // OWASP Reference: https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
        /*
        long rowID = db.insert(TABLE_NAME, "", values);
        */
        long rowID = db.insert(TABLE_NAME, "", sanitizeContentValues(values));
        if (rowID > 0) {
            Uri _uri = ContentUris.withAppendedId(CONTENT_URI, rowID);
            getContext().getContentResolver().notifyChange(_uri, null);
            return _uri;
        }
        throw new SQLException("Failed to add a record into " + uri);
    }

    @Override
    public boolean onCreate() {
        // VULNERABILITY: onCreate method lacks error handling for database creation failure.
        // OWASP Reference: https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control
        Context context = getContext();
        DatabaseHelper dbHelper = new DatabaseHelper(context);
        db = dbHelper.getWritableDatabase();
        if (db != null) {
            return true;
        }
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        // VULNERABILITY: Potential exposure of sensitive data through queries without proper access control.
        // OWASP Reference: https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control
        SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
        qb.setTables(TABLE_NAME);
        switch (uriMatcher.match(uri)) {
            case uriCode:
                // qb.setProjectionMap(values);
                qb.setProjectionMap(sanitizeProjectionMap(values));
                break;
            default:
                throw new IllegalArgumentException("Unknown URI " + uri);
        }
        if (sortOrder == null || sortOrder.equals("")) {
            sortOrder = name;
        }
        Cursor c = qb.query(db, projection, selection, selectionArgs, null, null, sortOrder);
        c.setNotificationUri(getContext().getContentResolver(), uri);
        return c;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // VULNERABILITY: Lack of input validation leading to SQL Injection risks in update method.
        // OWASP Reference: https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
        /*
        int count = db.update(TABLE_NAME, values, selection, selectionArgs);
        */
        int count = db.update(TABLE_NAME, sanitizeContentValues(values), sanitizeInput(selection), selectionArgs);
        getContext().getContentResolver().notifyChange(uri, null);
        return count;
    }

    private static class DatabaseHelper extends SQLiteOpenHelper {
        DatabaseHelper(Context context) {
            super(context, DATABASE_NAME, null, DATABASE_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(CREATE_DB_TABLE);
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            db.execSQL("DROP TABLE IF EXISTS " + TABLE_NAME);
            onCreate(db);
        }
    }

    // Sanitize methods to handle input safely

    // This method sanitizes input to prevent SQL injection
    private String sanitizeInput(String input) {
        // Escape single quotes by replacing them with two single quotes
        return input.replace("'", "''");
    }

    // This method sanitizes ContentValues to prevent SQL injection
    private ContentValues sanitizeContentValues(ContentValues values) {
        ContentValues sanitizedValues = new ContentValues();
        for (String key : values.keySet()) {
            Object value = values.get(key);
            if (value instanceof String) {
                // Sanitize string values
                sanitizedValues.put(key, sanitizeInput((String) value));
            } else {
                // For other types, we just put them directly
                sanitizedValues.put(key, value.toString());
            }
        }
        return sanitizedValues;
    }

    // This method sanitizes the projection map to prevent SQL injection
    private HashMap<String, String> sanitizeProjectionMap(HashMap<String, String> values) {
        HashMap<String, String> sanitizedMap = new HashMap<>();
        for (String key : values.keySet()) {
            // Sanitize map values
            sanitizedMap.put(key, sanitizeInput(values.get(key)));
        }
        return sanitizedMap;
    }
}