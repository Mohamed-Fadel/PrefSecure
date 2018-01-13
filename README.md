[![](https://jitpack.io/v/Mohamed-Fadel/PrefSecure.svg)](https://jitpack.io/#Mohamed-Fadel/PrefSecure)

# PrefSecure
Android Library for saving any Sensitive Data  (e.g user credentials, passwords, credit cards ,... etc) in cryptographic format

It is useful espically in case of rooted device, as the hacker can access your `SharedPreferences` and reach sensitive data easily. So this is a solution to keep your Data Safe.


# Usage
1. Init the `Singleton` in your `Application` Class by adding this line to the `onCreate()` Method in order to provide
   the Application `Context` in which this Singleton will operate.
```
@Override
public void onCreate() {
    super.onCreate();

    // Initialize the SecurePref Singleton..
    SecurePref.init(this);
}
  
```

2. Now you can use `SecurePref` Singleton all over the app by just Calling `SecurePref.getInstance()`
3. The `APIs` of SecurePref is the same as the `SharedPreference` apis. If you want for example set `accountNumber` as 
   a secure data you can do this:
```
SecurePref.getInstance().edit()
          .putLong("accountNumber", 123254589921L)
          .commit();
```
   and you can retreive the accountNumber later using this line:
```
SecurePref.getInstance().getLong("accountNumber", 0L);
```

# Gradle Dependency
1. Add the JitPack repository to your build file
   Add it in your root build.gradle at the end of repositories:
```
allprojects {
	repositories {
		...
		maven { url 'https://jitpack.io' }
	}
}
```
2. Add the dependency
```
dependencies {
	compile 'com.github.Mohamed-Fadel:PrefSecure:0.0.3@aar'
}
```

# Warning
- Supports +14 APIs but only encrypt the data for +18 APIs while save it as a `plainText` not encrypted for APIs < 18
- Encrypt only the values not the keys.
