# PrefSecure
Android Library For Saving any sensitive Data  (e.g user credentials, passwords, credit cards ,... etc) in cryptographic format

it is useful for rooted device where the hacker can access your `SharedPreferences` easily. So this is a solution to keep your `Data` Safe.


# Usage
1. init the `Singleton` in your `Application` Class by adding this line to the `onCreate()` Method in order to provide
   the Application `Context` in which this Singleton will operate.
```
@Override
public void onCreate() {
    super.onCreate();

    // Initialize the SecurePref Singleton..
    SecurePref.init(this);
}
  
```

2. Now you can use `SecurePref` Singelton all over the app by just Calling `SecurePref.getInstance()`
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

# Warning
- Supports +14 APIs but only encrypt the data for +18 APIs and save it as a `plainText` for APIs < 18
- Encrypt only the values not the keys.
