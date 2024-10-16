package com.security.insecurebankrs;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;

import com.security.insecurebankrs.FilePrefActivity;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Secure ChangePassword class
 */
public class ChangePassword extends Activity {
	EditText changePasswordText;
	TextView textViewUsername;
	Button changePasswordButton;

	// Regex for strong password
	private static final String PASSWORD_PATTERN =
			"((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{8,20})";
	private Pattern pattern;
	private Matcher matcher;

	String uname;
	String result;
	BufferedReader reader;
	String serverip = "";
	String serverport = "";
	String protocol = "https://";  // Use HTTPS for secure communication
	SharedPreferences serverDetails;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_change_password);

		try {
			// Use encrypted SharedPreferences for secure storage of sensitive data
			String masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);
			serverDetails = EncryptedSharedPreferences.create(
					"secure_prefs",
					masterKeyAlias,
					this,
					EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
					EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
			);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Get server details from encrypted SharedPreferences
		serverip = serverDetails.getString("serverip", null);
		serverport = serverDetails.getString("serverport", null);

		changePasswordText = findViewById(R.id.editText_newPassword);
		Intent intent = getIntent();
		uname = intent.getStringExtra("uname");
		textViewUsername = findViewById(R.id.textView_Username);
		textViewUsername.setText(uname);

		// Manage the change password button click
		changePasswordButton = findViewById(R.id.button_newPasswordSubmit);
		changePasswordButton.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				new RequestChangePasswordTask().execute(uname);
			}
		});
	}

	class RequestChangePasswordTask extends AsyncTask<String, String, String> {

		@Override
		protected String doInBackground(String... params) {
			try {
				postData(params[0]);
			} catch (Exception e) {
				Log.e("ChangePassword", "Error changing password", e);
			}
			return null;
		}

		@Override
		protected void onPostExecute(String result) {
			// Handle result if needed
		}

		public void postData(String username) throws Exception {
			HttpURLConnection urlConnection = null;
			try {
				URL url = new URL(protocol + serverip + ":" + serverport + "/changepassword");
				urlConnection = (HttpURLConnection) url.openConnection();
				urlConnection.setRequestMethod("POST");
				urlConnection.setDoOutput(true);
				urlConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

				// Hash the password
				String hashedPassword = hashPassword(changePasswordText.getText().toString());

				List<String> params = new ArrayList<>();
				params.add("username=" + username);
				params.add("newpassword=" + hashedPassword);
				byte[] postDataBytes = TextUtils.join("&", params).getBytes("UTF-8");

				urlConnection.getOutputStream().write(postDataBytes);

				InputStream in = urlConnection.getInputStream();
				result = convertStreamToString(in);
				result = result.replace("\n", "");

				runOnUiThread(() -> {
					if (result != null && result.contains("Change Password Successful")) {
						try {
							JSONObject jsonObject = new JSONObject(result);
							String message = jsonObject.getString("message");
							Toast.makeText(getApplicationContext(), message + ". Restart application to Continue.", Toast.LENGTH_LONG).show();

							TelephonyManager phoneManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
							String phoneNumber = phoneManager.getLine1Number();

							// Avoid sending sensitive information like passwords in SMS
							if (!TextUtils.isEmpty(phoneNumber)) {
								broadcastChangePasswordSMS(phoneNumber, "[REDACTED]");
							}

						} catch (JSONException e) {
							e.printStackTrace();
						}
					}
				});
			} finally {
				if (urlConnection != null) {
					urlConnection.disconnect();
				}
			}
		}

		private String convertStreamToString(InputStream in) throws IOException {
			reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
			StringBuilder sb = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
			}
			in.close();
			return sb.toString();
		}

		private String hashPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
			int iterations = 1000;
			char[] chars = password.toCharArray();
			byte[] salt = getSalt();

			PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			byte[] hash = skf.generateSecret(spec).getEncoded();
			return Base64.encodeToString(hash, Base64.DEFAULT);
		}

		private byte[] getSalt() throws NoSuchAlgorithmException {
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			byte[] salt = new byte[16];
			sr.nextBytes(salt);
			return salt;
		}
	}

	private void broadcastChangePasswordSMS(String phoneNumber, String message) {
		// Never send passwords via SMS
		Intent smsIntent = new Intent();
		smsIntent.setAction("theBroadcast");
		smsIntent.putExtra("phonenumber", phoneNumber);
		smsIntent.putExtra("message", message);
		sendBroadcast(smsIntent);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			callPreferences();
			return true;
		} else if (id == R.id.action_exit) {
			Intent i = new Intent(getBaseContext(), LoginActivity.class);
			i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
			startActivity(i);
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	public void callPreferences() {
		Intent i = new Intent(this, FilePrefActivity.class);
		startActivity(i);
	}
}