#include <jni.h>
#include <string>
#include "MyLoader.h"


extern "C" JNIEXPORT jstring

JNICALL
Java_ng1ok_linker_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}


extern "C"
JNIEXPORT void JNICALL
Java_ng1ok_linker_MainActivity_test(JNIEnv *env, jobject thiz) {
    MyLoader myLoader;
    myLoader.run("/data/local/tmp/libdemo1.so");

    LOGD("test done....");

}