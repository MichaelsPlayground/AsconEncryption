package de.androidcrypto.asconencryption;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "AsconExample";
    TextView textViewConsole, runtimeWarning;
    String consoleText = "";
    String APPTITLE = "Ascon Encryption Example";
    Context contextSave;
    AutoCompleteTextView chooseAlgorithm;
    String choiceString;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);
        contextSave = getApplicationContext();

        textViewConsole = findViewById(R.id.textviewConsole);
        runtimeWarning = findViewById(R.id.tvMainWarningEn);

        String[] type = new String[]{"choose an algorithm to run",
                "Ascon128v12",
                "Ascon128av12",
        };

        ArrayAdapter<String> arrayAdapter = new ArrayAdapter<>(
                this,
                R.layout.drop_down_item,
                type);

        chooseAlgorithm = findViewById(R.id.chooseAlgorithm);
        chooseAlgorithm.setAdapter(arrayAdapter);
        chooseAlgorithm.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> adapterView, View view, int i, long l) {
                String choiceString = chooseAlgorithm.getText().toString();
                runtimeWarning.setVisibility(View.GONE);
                switch (choiceString) {

                    case "Ascon128v12": {
                        clearConsole();

                        printlnX("\n* ASCON128v12 AEAD authenticated encryption *\n");
                        printlnX("\nrunning on " + getAndroidVersion());
                        printlnX("all values are in string or hex encoding\n");
                        String plaintextString = "This are 17 chars";
                        String additionalDataString = "ABC";
                        byte[] plaintext = plaintextString.getBytes(StandardCharsets.UTF_8);
                        byte[] additionalData = additionalDataString.getBytes(StandardCharsets.UTF_8);

                        byte[] key = "1234567890123456".getBytes(StandardCharsets.UTF_8);
                        byte[] nonce = "6543210987654321".getBytes(StandardCharsets.UTF_8);
                        byte[] completeCiphertext;
                        byte[] decryptedtext;
                        completeCiphertext = ascon128v12Encryption(key, nonce, plaintext, additionalData);

                        printlnX("plaintext:  " + plaintextString);
                        printlnX("plaintext:  " + bytesToHex(plaintext));
                        printlnX("aead:       " + additionalDataString);
                        printlnX("aead:       " + bytesToHex(additionalData));
                        printlnX("key:        " + bytesToHex(key));
                        printlnX("keyLen:     " + key.length);
                        printlnX("nonce:      " + bytesToHex(nonce));
                        printlnX("nonceLen:   " + nonce.length);
                        printlnX("ciphertext: " + bytesToHex(completeCiphertext));
                        printlnX("ciphertLen: " + completeCiphertext.length);

                        decryptedtext = ascon128v12Decryption(key, nonce, completeCiphertext, additionalData);
                        printlnX("decrypText: " + bytesToHex(decryptedtext));
                        printlnX("decrypText: " + new String(decryptedtext, StandardCharsets.UTF_8));

                        // split the completeCiphertext in ciphertext and authentication tag
                        byte[] ciphertext = new byte[(completeCiphertext.length - Ascon128v12.CRYPTO_ABYTES)];
                        byte[] authenticationTag = new byte[Ascon128v12.CRYPTO_ABYTES];
                        ascon128v12SplitCiphertext(completeCiphertext, ciphertext, authenticationTag);

                        // combine the ciphertext and authenticationTag to completeCiphertext
                        byte[] completeCiphertextConcat = new byte[(ciphertext.length + Ascon128v12.CRYPTO_ABYTES)];
                        ascon128v12ConcatenateCiphertext(completeCiphertextConcat, ciphertext, authenticationTag);
                        // run the decryption
                        byte[] decryptedtextConcat;
                        decryptedtextConcat = ascon128v12Decryption(key, nonce, completeCiphertextConcat, additionalData);

                        printlnX("-------- complete ciphertext split --------");
                        printlnX("ciphertext: " + bytesToHex(ciphertext));
                        printlnX("ciphertLen: " + ciphertext.length);
                        printlnX("authTag:    " + bytesToHex(authenticationTag));
                        printlnX("authTagLen: " + authenticationTag.length);
                        printlnX("decrypText: " + bytesToHex(decryptedtextConcat));
                        printlnX("decrypText: " + new String(decryptedtextConcat, StandardCharsets.UTF_8));
                        printlnX("-------- complete ciphertext split end ----");

                        printlnX("\n** wrong additional data for decryption **");
                        String additionalDataWrongString = "ABD";
                        byte[] additionalDataWrong = additionalDataWrongString.getBytes(StandardCharsets.UTF_8);
                        decryptedtext = ascon128v12Decryption(key, nonce, completeCiphertext, additionalDataWrong);
                        printlnX("aead wrong: " + bytesToHex(additionalDataWrong));
                        printlnX("decrypText: " + bytesToHex(decryptedtext));
                        printlnX("decrypText: " + new String(decryptedtext, StandardCharsets.UTF_8));

                        printlnX("\n** wrong key for decryption **");
                        byte[] keyWrong = "1234567890123457".getBytes(StandardCharsets.UTF_8);
                        decryptedtext = ascon128v12Decryption(keyWrong, nonce, completeCiphertext, additionalData);
                        printlnX("key wrong:  " + bytesToHex(keyWrong));
                        printlnX("decrypText: " + bytesToHex(decryptedtext));
                        printlnX("decrypText: " + new String(decryptedtext, StandardCharsets.UTF_8));

                        printlnX("\n** wrong nonce for decryption **");
                        byte[] nonceyWrong = "6543210987654320".getBytes(StandardCharsets.UTF_8);
                        decryptedtext = ascon128v12Decryption(key, nonceyWrong, completeCiphertext, additionalData);
                        printlnX("nonce wrong:" + bytesToHex(nonceyWrong));
                        printlnX("decrypText: " + bytesToHex(decryptedtext));
                        printlnX("decrypText: " + new String(decryptedtext, StandardCharsets.UTF_8));

                        break;
                    }

                    case "Ascon128av12": {
                        clearConsole();

                        printlnX("\n* ASCON128av12 AEAD authenticated encryption *\n");
                        printlnX("\nrunning on " + getAndroidVersion());
                        printlnX("all values are in string or hex encoding\n");
                        String plaintextString = "This are 17 chars";
                        String additionalDataString = "ABC";
                        byte[] plaintext = plaintextString.getBytes(StandardCharsets.UTF_8);
                        byte[] additionalData = additionalDataString.getBytes(StandardCharsets.UTF_8);

                        byte[] key = "1234567890123456".getBytes(StandardCharsets.UTF_8);
                        byte[] nonce = "6543210987654321".getBytes(StandardCharsets.UTF_8);
                        byte[] completeCiphertext;
                        byte[] decryptedtext;
                        completeCiphertext = ascon128av12Encryption(key, nonce, plaintext, additionalData);

                        printlnX("plaintext:  " + plaintextString);
                        printlnX("plaintext:  " + bytesToHex(plaintext));
                        printlnX("aead:       " + additionalDataString);
                        printlnX("aead:       " + bytesToHex(additionalData));
                        printlnX("key:        " + bytesToHex(key));
                        printlnX("keyLen:     " + key.length);
                        printlnX("nonce:      " + bytesToHex(nonce));
                        printlnX("nonceLen:   " + nonce.length);
                        printlnX("ciphertext: " + bytesToHex(completeCiphertext));
                        printlnX("ciphertLen: " + completeCiphertext.length);
                        decryptedtext = ascon128av12Decryption(key, nonce, completeCiphertext, additionalData);
                        printlnX("decrypText: " + bytesToHex(decryptedtext));
                        printlnX("decrypText: " + new String(decryptedtext, StandardCharsets.UTF_8));

                        // split the completeCiphertext in ciphertext and authentication tag
                        byte[] ciphertext = new byte[(completeCiphertext.length - Ascon128av12.CRYPTO_ABYTES)];
                        byte[] authenticationTag = new byte[Ascon128av12.CRYPTO_ABYTES];
                        ascon128av12SplitCiphertext(completeCiphertext, ciphertext, authenticationTag);

                        // combine the ciphertext and authenticationTag to completeCiphertext
                        byte[] completeCiphertextConcat = new byte[(ciphertext.length + Ascon128av12.CRYPTO_ABYTES)];
                        ascon128av12ConcatenateCiphertext(completeCiphertextConcat, ciphertext, authenticationTag);
                        // run the decryption
                        byte[] decryptedtextConcat;
                        decryptedtextConcat = ascon128av12Decryption(key, nonce, completeCiphertextConcat, additionalData);

                        printlnX("-------- complete ciphertext split --------");
                        printlnX("ciphertext: " + bytesToHex(ciphertext));
                        printlnX("ciphertLen: " + ciphertext.length);
                        printlnX("authTag:    " + bytesToHex(authenticationTag));
                        printlnX("authTagLen: " + authenticationTag.length);
                        printlnX("decrypText: " + bytesToHex(decryptedtextConcat));
                        printlnX("decrypText: " + new String(decryptedtextConcat, StandardCharsets.UTF_8));
                        printlnX("-------- complete ciphertext split end ----");

                        printlnX("\n** wrong additional data for decryption **");
                        String additionalDataWrongString = "ABD";
                        byte[] additionalDataWrong = additionalDataWrongString.getBytes(StandardCharsets.UTF_8);
                        decryptedtext = ascon128v12Decryption(key, nonce, completeCiphertext, additionalDataWrong);
                        printlnX("aead wrong: " + bytesToHex(additionalDataWrong));
                        printlnX("decrypText: " + bytesToHex(decryptedtext));
                        printlnX("decrypText: " + new String(decryptedtext, StandardCharsets.UTF_8));

                        printlnX("\n** wrong key for decryption **");
                        byte[] keyWrong = "1234567890123457".getBytes(StandardCharsets.UTF_8);
                        decryptedtext = ascon128v12Decryption(keyWrong, nonce, completeCiphertext, additionalData);
                        printlnX("key wrong:  " + bytesToHex(keyWrong));
                        printlnX("decrypText: " + bytesToHex(decryptedtext));
                        printlnX("decrypText: " + new String(decryptedtext, StandardCharsets.UTF_8));

                        printlnX("\n** wrong nonce for decryption **");
                        byte[] nonceyWrong = "6543210987654320".getBytes(StandardCharsets.UTF_8);
                        decryptedtext = ascon128v12Decryption(key, nonceyWrong, completeCiphertext, additionalData);
                        printlnX("nonce wrong:" + bytesToHex(nonceyWrong));
                        printlnX("decrypText: " + bytesToHex(decryptedtext));
                        printlnX("decrypText: " + new String(decryptedtext, StandardCharsets.UTF_8));
                        break;
                    }

                    default: {

                        break;
                    }
                }
            }
        });
    }



    /**
     * section for ASCON-128 V12
     */

    /**
     * the method encrypts plaintext using the algorithm ASCON128V12
     * @param key 16 bytes long
     * @param nonce 16 bytes long
     * @param plaintext
     * @param additionalData (note: if providing additional data on encryption you have to provide the same data for decryption)
     * @return the ciphertext
     */

    private byte[] ascon128v12Encryption(@NonNull byte[] key, @NonNull byte[] nonce, @NonNull byte[] plaintext, byte[] additionalData) {
        // sanity checks
        if (key.length != 16) {
            Log.e(TAG, "the key length has to be 16, found " + key.length);
            return new byte[0];
        }
        if (nonce.length != 16) {
            Log.e(TAG, "the nonce length has to be 16, found " + nonce.length);
            return new byte[0];
        }
        int additionalDataLength;
        if (additionalData == null) {
            additionalDataLength = 0;
        } else {
            additionalDataLength = additionalData.length;
        }
        byte[] s = {};
        byte[] ciphertext = new byte[plaintext.length + Ascon128v12.CRYPTO_ABYTES];
        int clen = Ascon128v12.crypto_aead_encrypt(ciphertext, ciphertext.length, plaintext, plaintext.length, additionalData, additionalDataLength, s, nonce, key);
        return ciphertext;
    }

    /**
     * the method decrypts ciphertext using the algorithm ASCON128V12
     * @param key 16 bytes long
     * @param nonce 16 bytes long
     * @param ciphertext
     * @param additionalData (note: if providing additional data on encryption you have to provide the same data for decryption)
     * @return the decryptedtext = plaintext
     */
    private byte[] ascon128v12Decryption(@NonNull byte[] key, @NonNull byte[] nonce, @NonNull byte[] ciphertext, byte[] additionalData) {
        // sanity checks
        if (key.length != 16) {
            Log.e(TAG, "the key length has to be 16, found " + key.length);
            return new byte[0];
        }
        if (nonce.length != 16) {
            Log.e(TAG, "the nonce length has to be 16, found " + nonce.length);
            return new byte[0];
        }
        int additionalDataLength;
        if (additionalData == null) {
            additionalDataLength = 0;
        } else {
            additionalDataLength = additionalData.length;
        }
        byte[] s = {};
        byte[] plaintext = new byte[ciphertext.length + Ascon128v12.CRYPTO_ABYTES];
        int plen = Ascon128v12.crypto_aead_decrypt(plaintext, plaintext.length, s, ciphertext, ciphertext.length, additionalData, additionalDataLength, nonce, key);
        if (plen != -1) {
            return Arrays.copyOfRange(plaintext, 0, plen);
        } else {
            return new byte[0];
        }
    }

    /**
     * the method splits the completeCiphertext in ciphertext and authenticationTag
     * @param completeCiphertext the complete ciphertext with concatenated ciphertext | authenticationTag
     * @param ciphertext an empty byte array with length of (completeCiphertext length - Ascon128v12.CRYPTO_ABYTES)
     * @param authenticationTag an empty byte array with length of Ascon128v12.CRYPTO_ABYTES = 16 bytes long
     * @return length of ciphertext or 0 if something was wrong
     */
    private int ascon128v12SplitCiphertext(@NonNull byte[] completeCiphertext, byte[] ciphertext, byte[] authenticationTag) {
        final int AUTHTAG_LENGTH = Ascon128v12.CRYPTO_ABYTES; // should be 16
        // sanity checks
        int completeCiphertextLength = completeCiphertext.length;
        if (completeCiphertextLength <= AUTHTAG_LENGTH) {
            Log.e(TAG, "the completeCiphertext is too short");
            return 0;
        }
        int ciphertextLength = ciphertext.length;
        int authenticationTagLength = authenticationTag.length;
        if (ciphertext.length != (completeCiphertextLength - AUTHTAG_LENGTH)) {
            Log.e(TAG, "ciphertext length does not fit, should be " +
                    (completeCiphertextLength - AUTHTAG_LENGTH) +
                    " but found " + ciphertextLength);
            return 0;
        }
        if (authenticationTagLength != (AUTHTAG_LENGTH)) {
            Log.e(TAG, "authenticationTag length does not fit, should be " +
                    AUTHTAG_LENGTH +
                    " but found " + authenticationTagLength);
            return 0;
        }
        System.arraycopy(completeCiphertext, 0, ciphertext, 0, (completeCiphertextLength - AUTHTAG_LENGTH));
        System.arraycopy(completeCiphertext, (completeCiphertextLength - AUTHTAG_LENGTH), authenticationTag, 0, AUTHTAG_LENGTH);
        return ciphertextLength;
    }

    /**
     * the method concatenates ciphertext and authenticationTag to completeCiphertext
     * @param completeCiphertext the complete ciphertext with concatenated ciphertext | authenticationTag, an empty byte array with a length of ciphertext length + Ascon128v12.CRYPTO_ABYTES
     * @param ciphertext an byte array with a minimum length of 1
     * @param authenticationTag an byte array with the authenticationTag of a length of Ascon128v12.CRYPTO_ABYTES = 16 bytes long
     * @return length of completeCiphertext or 0 if something was wrong
     */
    private int ascon128v12ConcatenateCiphertext(@NonNull byte[] completeCiphertext, byte[] ciphertext, byte[] authenticationTag) {
        final int AUTHTAG_LENGTH = Ascon128v12.CRYPTO_ABYTES; // should be 16
        // sanity checks
        int ciphertextLength = ciphertext.length;
        int authenticationTagLength = authenticationTag.length;
        if (ciphertext.length < 1) {
            Log.e(TAG, "ciphertext is too short (found 0 bytes length");
            return 0;
        }
        if (authenticationTagLength != (AUTHTAG_LENGTH)) {
            Log.e(TAG, "authenticationTag length does not fit, should be " +
                    AUTHTAG_LENGTH +
                    " but found " + authenticationTagLength);
            return 0;
        }
        int completeCiphertextLength = completeCiphertext.length;
        if (completeCiphertextLength != (ciphertextLength + AUTHTAG_LENGTH)) {
            Log.e(TAG, "the completeCiphertext length does not fit is, should be " +
                    (ciphertextLength + AUTHTAG_LENGTH) +
                    " but found " + completeCiphertextLength);
            return 0;
        }
        System.arraycopy(ciphertext, 0, completeCiphertext, 0, ciphertextLength);
        System.arraycopy(authenticationTag, 0, completeCiphertext, ciphertextLength, AUTHTAG_LENGTH);
        return completeCiphertextLength;
    }


    /**
     * section for ASCON-128 AV12
     */

    /**
     * the method encrypts plaintext using the algorithm ASCON128AV12
     * @param key 16 bytes long
     * @param nonce 16 bytes long
     * @param plaintext
     * @param additionalData (note: if providing additional data on encryption you have to provide the same data for decryption)
     * @return the ciphertext
     */
    private byte[] ascon128av12Encryption(@NonNull byte[] key, @NonNull byte[] nonce, @NonNull byte[] plaintext, byte[] additionalData) {
        // sanity checks
        if (key.length != 16) {
            Log.e(TAG, "the key length has to be 16, found " + key.length);
            return new byte[0];
        }
        if (nonce.length != 16) {
            Log.e(TAG, "the nonce length has to be 16, found " + nonce.length);
            return new byte[0];
        }
        int additionalDataLength;
        if (additionalData == null) {
            additionalDataLength = 0;
        } else {
            additionalDataLength = additionalData.length;
        }
        byte[] s = {};
        byte[] ciphertext = new byte[plaintext.length + Ascon128av12.CRYPTO_ABYTES];
        int clen = Ascon128av12.crypto_aead_encrypt(ciphertext, ciphertext.length, plaintext, plaintext.length, additionalData, additionalDataLength, s, nonce, key);
        return ciphertext;
    }

    /**
     * the method decrypts ciphertext using the algorithm ASCON128AV12
     * @param key 16 bytes long
     * @param nonce 16 bytes long
     * @param ciphertext
     * @param additionalData (note: if providing additional data on encryption you have to provide the same data for decryption)
     * @return the decryptedtext = plaintext
     */
    private byte[] ascon128av12Decryption(@NonNull byte[] key, @NonNull byte[] nonce, @NonNull byte[] ciphertext, byte[] additionalData) {
        // sanity checks
        if (key.length != 16) {
            Log.e(TAG, "the key length has to be 16, found " + key.length);
            return new byte[0];
        }
        if (nonce.length != 16) {
            Log.e(TAG, "the nonce length has to be 16, found " + nonce.length);
            return new byte[0];
        }
        int additionalDataLength;
        if (additionalData == null) {
            additionalDataLength = 0;
        } else {
            additionalDataLength = additionalData.length;
        }
        byte[] s = {};
        byte[] plaintext = new byte[ciphertext.length + Ascon128av12.CRYPTO_ABYTES];
        int plen = Ascon128av12.crypto_aead_decrypt(plaintext, plaintext.length, s, ciphertext, ciphertext.length, additionalData, additionalDataLength, nonce, key);
        if (plen != -1) {
            return Arrays.copyOfRange(plaintext, 0, plen);
        } else {
            return new byte[0];
        }
    }

    /**
     * the method splits the completeCiphertext in ciphertext and authenticationTag
     * @param completeCiphertext the complete ciphertext with concatenated ciphertext | authenticationTag
     * @param ciphertext an empty byte array with length of (completeCiphertext length - Ascon128av12.CRYPTO_ABYTES)
     * @param authenticationTag an empty byte array with length of Ascon128av12.CRYPTO_ABYTES = 16 bytes long
     * @return length of ciphertext or 0 if something was wrong
     */
    private int ascon128av12SplitCiphertext(@NonNull byte[] completeCiphertext, byte[] ciphertext, byte[] authenticationTag) {
        final int AUTHTAG_LENGTH = Ascon128av12.CRYPTO_ABYTES; // should be 16
        // sanity checks
        int completeCiphertextLength = completeCiphertext.length;
        if (completeCiphertextLength <= AUTHTAG_LENGTH) {
            Log.e(TAG, "the completeCiphertext is too short");
            return 0;
        }
        int ciphertextLength = ciphertext.length;
        int authenticationTagLength = authenticationTag.length;
        if (ciphertext.length != (completeCiphertextLength - AUTHTAG_LENGTH)) {
            Log.e(TAG, "ciphertext length does not fit, should be " +
                    (completeCiphertextLength - AUTHTAG_LENGTH) +
                    " but found " + ciphertextLength);
            return 0;
        }
        if (authenticationTagLength != (AUTHTAG_LENGTH)) {
            Log.e(TAG, "authenticationTag length does not fit, should be " +
                    AUTHTAG_LENGTH +
                    " but found " + authenticationTagLength);
            return 0;
        }
        System.arraycopy(completeCiphertext, 0, ciphertext, 0, (completeCiphertextLength - AUTHTAG_LENGTH));
        System.arraycopy(completeCiphertext, (completeCiphertextLength - AUTHTAG_LENGTH), authenticationTag, 0, AUTHTAG_LENGTH);
        return ciphertextLength;
    }

    /**
     * the method concatenates ciphertext and authenticationTag to completeCiphertext
     * @param completeCiphertext the complete ciphertext with concatenated ciphertext | authenticationTag, an empty byte array with a length of ciphertext length + Ascon128av12.CRYPTO_ABYTES
     * @param ciphertext an byte array with a minimum length of 1
     * @param authenticationTag an byte array with the authenticationTag of a length of Ascon128av12.CRYPTO_ABYTES = 16 bytes long
     * @return length of completeCiphertext or 0 if something was wrong
     */
    private int ascon128av12ConcatenateCiphertext(@NonNull byte[] completeCiphertext, byte[] ciphertext, byte[] authenticationTag) {
        final int AUTHTAG_LENGTH = Ascon128av12.CRYPTO_ABYTES; // should be 16
        // sanity checks
        int ciphertextLength = ciphertext.length;
        int authenticationTagLength = authenticationTag.length;
        if (ciphertext.length < 1) {
            Log.e(TAG, "ciphertext is too short (found 0 bytes length");
            return 0;
        }
        if (authenticationTagLength != (AUTHTAG_LENGTH)) {
            Log.e(TAG, "authenticationTag length does not fit, should be " +
                    AUTHTAG_LENGTH +
                    " but found " + authenticationTagLength);
            return 0;
        }
        int completeCiphertextLength = completeCiphertext.length;
        if (completeCiphertextLength != (ciphertextLength + AUTHTAG_LENGTH)) {
            Log.e(TAG, "the completeCiphertext length does not fit is, should be " +
                    (ciphertextLength + AUTHTAG_LENGTH) +
                    " but found " + completeCiphertextLength);
            return 0;
        }
        System.arraycopy(ciphertext, 0, completeCiphertext, 0, ciphertextLength);
        System.arraycopy(authenticationTag, 0, completeCiphertext, ciphertextLength, AUTHTAG_LENGTH);
        return completeCiphertextLength;
    }

    /**
     * general code
     */

    public void clearConsole() {
        consoleText = "";
        textViewConsole.setText(consoleText);
        MainActivity.this.setTitle(APPTITLE);
    }

    public void printlnX(String print) {
        consoleText = consoleText + print + "\n";
        textViewConsole.setText(consoleText);
        System.out.println();
    }

    private static String getAndroidVersion() {
        String release = Build.VERSION.RELEASE;
        int sdkVersion = Build.VERSION.SDK_INT;
        return "Android SDK: " + sdkVersion + " (" + release + ")";
    }

    /**
     * section for toolbar menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mExportMail = menu.findItem(R.id.action_export_mail);
        mExportMail.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                exportDumpMail();
                return false;
            }
        });

        MenuItem mExportFile = menu.findItem(R.id.action_export_file);
        mExportFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                exportDumpFile();
                return false;
            }
        });
        return super.onCreateOptionsMenu(menu);
    }

    private void exportDumpMail() {
        if (consoleText.isEmpty()) {
            writeToUiToast("run an entry before sending emails :-)");
            return;
        }
        String subject = "Ascon Encryption Example";
        String body = consoleText;
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, subject);
        intent.putExtra(Intent.EXTRA_TEXT, body);
        if (intent.resolveActivity(getPackageManager()) != null) {
            startActivity(intent);
        }
    }

    private void exportDumpFile() {
        if (consoleText.isEmpty()) {
            writeToUiToast("run an entry before writing files :-)");
            return;
        }
        writeStringToExternalSharedStorage();
    }

    private void writeStringToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        // boolean pickerInitialUri = false;
        // intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = "ascon" + ".txt";
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("run an entry before writing the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        fileSaverActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> fileSaverActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            try {
                                // get file content from edittext
                                String fileContent = consoleText;
                                writeTextToUri(uri, fileContent);
                                String message = "file written to external shared storage: " + uri.toString();
                                writeToUiToast(message);
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("ERROR: " + e.toString());
                                return;
                            }
                        }
                    }
                }
            });

    private void writeTextToUri(Uri uri, String data) throws IOException {
        try {
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(contextSave.getContentResolver().openOutputStream(uri));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            System.out.println("Exception File write failed: " + e.toString());
        }
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    /* ############# your code comes below ####################
       change all code: System.out.println("something");
       to printlnX("something");
     */
    // place your main method here
    private void runMain() {

        printlnX("Android version: " + getAndroidVersion());

    }
    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private static byte[] hexToBytes(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(str.substring(2 * i, 2 * i + 2),
                    16);
        }
        return bytes;
    }

}