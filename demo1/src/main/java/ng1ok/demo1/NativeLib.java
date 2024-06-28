package ng1ok.demo1;

public class NativeLib {

    // Used to load the 'demo1' library on application startup.
    static {
        System.loadLibrary("demo1");
    }

    /**
     * A native method that is implemented by the 'demo1' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}