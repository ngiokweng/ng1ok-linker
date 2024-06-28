package ng1ok.linker;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;


import ng1ok.linker.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'linker' library on application startup.
    static {
        System.loadLibrary("nglinker");
//        System.loadLibrary("demo1");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI());
        test();
        demo1Func();
    }
    public native String demo1Func();
    /**
     * A native method that is implemented by the 'linker' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public native void test();



}