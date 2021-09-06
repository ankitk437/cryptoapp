package com.example.cryptography;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);



    }
    Intent intent;
    public void asymmetric(View view) {
        intent=new Intent(this,Asymmetric.class);
        startActivity(intent);
    }

    public void hash(View view) {
        intent =new Intent(this,Hash.class);
        startActivity(intent);
    }

    public void symmetric(View view) {
        intent=new Intent(this,Symmetric.class);
        startActivity(intent);
    }
}