package com.example.cryptography;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class Hash extends AppCompatActivity {
    EditText text;
    Spinner method;
    EditText number;
    TextView ans;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hash);
        text = (EditText)findViewById(R.id.hash_text);
        method=(Spinner)findViewById(R.id.hash_method);
        method.setSelection(1);
        number = (EditText)findViewById(R.id.hash_number);
        ans=(TextView)findViewById(R.id.has_ans);

    }





    public void encrypt(View view) {
        String s=text.getText().toString();
        final String Method =method.getSelectedItem().toString();
        int num=Integer.parseInt(number.getText().toString());
        try {
            // Create MD5 Hash
            MessageDigest digest;
            digest = MessageDigest
                    .getInstance(Method);
            digest.update(s.getBytes("UTF-8"));
            byte messageDigest[]=digest.digest();

           String rt= new String(messageDigest, "UTF-8");
            // Create Hex String
          ans.setText(rt);

        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {

            e.printStackTrace();
            Toast.makeText(this, "some error occur",
                    Toast.LENGTH_LONG).show();
        }

    }
}