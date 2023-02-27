package com.solanamobile.keystoreattestationsample

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import androidx.appcompat.widget.AppCompatButton
import com.google.android.material.snackbar.Snackbar
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<AppCompatButton>(R.id.btn_generate_attested_keypair).setOnClickListener {
            onGenerateKeystoreAttestedKey(it)
        }
    }

    private fun onGenerateKeystoreAttestedKey(view: View) {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
            "test",
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).setAttestationChallenge(
            "Some challenge bytes".toByteArray(Charsets.UTF_8)
        ).setDevicePropertiesAttestationIncluded(true
        ).setIsStrongBoxBacked(true
        ).build()

        kpg.initialize(parameterSpec)

        val keypair = kpg.generateKeyPair()

        val keystore = KeyStore.getInstance("AndroidKeyStore")
        keystore.load(null)

        keystore.getCertificateChain("test").forEachIndexed { i, cert ->
            cert as X509Certificate
            Log.d("KEY", "[CERT $i]")
            Log.d("KEY", cert.toString())
            Log.d("KEY", "Encoded = ${cert.encoded.joinToString(separator = " ") { 
                it.toUByte().toString(16).padStart(2, '0') } 
            }")

            // If present, log the Keystore Attestation Extension
            try {
                Log.d(
                    "KEY",
                    "OID 1.3.6.1.4.1.11129.2.1.17 = ${
                        cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
                            .joinToString(separator = " ") { it.toUByte().toString(16).padStart(2, '0') }
                    }"
                )
            } catch (e: NullPointerException) {}
        }

        Snackbar.make(view, R.string.check_logcat, Snackbar.LENGTH_SHORT).show()
    }
}