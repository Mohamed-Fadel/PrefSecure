package com.mohamedfadel91.prefsecure;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Looper;
import android.support.annotation.MainThread;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;

import com.mohamedfadel91.prefsecure.utils.Utils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Created by Fadel on 04/01/18.
 * This is SecurePref Where You Could save your data safely..
 */

public class SecurePref implements SharedPreferences {

    @SuppressLint("StaticFieldLeak")
    private static SecurePref prefInstance;
    private static Context appContext;
    private static String KEY_ALIAS;

    @NonNull
    private final SharedPreferences mPref;

    private SecurePref() {
        // mentioned to block creating objects..
        mPref = appContext.getSharedPreferences("securePref",
                Context.MODE_PRIVATE);

        Utils.createKey(appContext, KEY_ALIAS);
    }

    @MainThread
    public static SecurePref getInstance() {
        if (Looper.getMainLooper().getThread() != Thread.currentThread()) {
            // Current Thread is Main Thread.
            throw new IllegalThreadStateException("You must call this method from the MainThread Only");
        }
        if (appContext == null || KEY_ALIAS == null) {
            throw new IllegalStateException("You must call init() method firstly");
        }
        if (prefInstance == null) {
            synchronized (SecurePref.class) {
                if (prefInstance == null) {
                    prefInstance = new SecurePref();
                }
            }
        }
        return prefInstance;
    }

    @MainThread
    public static void init(@NonNull Context context) {
        appContext = context.getApplicationContext();
        KEY_ALIAS = appContext.getApplicationContext().getApplicationInfo().packageName
                + "_" + "my_secure_key";
    }

    @Override
    public Map<String, ?> getAll() {
        Map<String, ?> map = mPref.getAll();
        if (map == null) return null;

        Map<String, Object> result = new HashMap<>();
        Iterator iterator = map.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, ?> entry = (Map.Entry<String, ?>) iterator.next();
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof String) {
                result.put(key, decryptToString((String) value));
            } else {
                result.put(key, value);
            }
        }

        return result;
    }

    @Nullable
    @Override
    public String getString(String key, @Nullable String defValue) {
        if (!mPref.contains(key)) return defValue;
        String cipherText = mPref.getString(key, defValue);
        assert cipherText != null;
        return decryptToString(cipherText);
    }


    @Nullable
    @Override
    public Set<String> getStringSet(String key, @Nullable Set<String> defValues) {
        if (!mPref.contains(key)) {
            return defValues;
        }
        Set<String> values = mPref.getStringSet(key, defValues);

        assert values != null;
        Iterator iterator = values.iterator();

        Set<String> result = new HashSet<>();
        while (iterator.hasNext()) {
            result.add(decryptToString((String) iterator.next()));
        }
        return result;
    }

    @Override
    public int getInt(String key, int defValue) {
        if (!mPref.contains(key)) return defValue;
        String cipherText = mPref.getString(key, String.valueOf(defValue));
        String result = decryptToString(cipherText);
        int output = defValue;
        try {
            output = Integer.parseInt(result);
        } catch (NumberFormatException ignored) {
        }
        return output;
    }


    @Override
    public long getLong(String key, long defValue) {
        if (!mPref.contains(key)) return defValue;
        String cipherText = mPref.getString(key, String.valueOf(defValue));
        String result = decryptToString(cipherText);
        long output = defValue;
        try {
            output = Long.parseLong(result);
        } catch (NumberFormatException ignored) {
        }
        return output;
    }

    @Override
    public float getFloat(String key, float defValue) {
        if (!mPref.contains(key)) return defValue;
        String cipherText = mPref.getString(key, String.valueOf(defValue));
        String result = decryptToString(cipherText);
        float output = defValue;
        try {
            output = Float.parseFloat(result);
        } catch (NullPointerException | NumberFormatException ignored) {
        }
        return output;
    }

    @Override
    public boolean getBoolean(String key, boolean defValue) {
        if (!mPref.contains(key)) return defValue;
        String cipherText = mPref.getString(key, String.valueOf(defValue));
        String result = decryptToString(cipherText);
        boolean output = defValue;
        try {
            output = Boolean.parseBoolean(result);
        } catch (Exception ignored) {
        }
        return output;
    }

    @Override
    public boolean contains(String key) {
        return mPref.contains(key);
    }

    @Override
    public Editor edit() {
        return new Editor();
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        mPref.registerOnSharedPreferenceChangeListener(listener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        mPref.unregisterOnSharedPreferenceChangeListener(listener);
    }

    @SuppressLint("CommitPrefEdits")
    public class Editor implements SharedPreferences.Editor {

        private final SharedPreferences.Editor editor;

        private Editor() {
            editor = mPref.edit();
        }

        @Override
        public SecurePref.Editor putString(String key, @Nullable String value) {
            if (value == null) {
                remove(key);
                return this;
            }
            editor.putString(key, encryptToString(value));
            return this;
        }

        @Override
        public SecurePref.Editor putStringSet(String key, @Nullable Set<String> values) {
            if (values == null) {
                remove(key);
                return this;
            }
            Set<String> incValues = new HashSet<>();
            Iterator iterator = values.iterator();
            while (iterator.hasNext()) {
                String value = (String) iterator.next();
                incValues.add(encryptToString(value));
            }
            editor.putStringSet(key, incValues);
            return this;
        }

        @Override
        public SecurePref.Editor putInt(String key, int value) {
            editor.putString(key, encryptToString(String.valueOf(value)));
            return this;
        }

        @Override
        public SecurePref.Editor putLong(String key, long value) {
            editor.putString(key, encryptToString(String.valueOf(value)));
            return this;
        }

        @Override
        public SecurePref.Editor putFloat(String key, float value) {
            editor.putString(key, encryptToString(String.valueOf(value)));
            return this;
        }

        @Override
        public SecurePref.Editor putBoolean(String key, boolean value) {
            editor.putString(key, encryptToString(String.valueOf(value)));
            return this;
        }

        @Override
        public SecurePref.Editor remove(String key) {
            editor.remove(key);
            return this;
        }

        @Override
        public SecurePref.Editor clear() {
            editor.clear();
            return this;
        }

        @Override
        public boolean commit() {
            return editor.commit();
        }

        @Override
        public void apply() {
            editor.apply();
        }

    }

    @NonNull
    private String decryptToString(@NonNull String cipherText) {
        byte[] result = Utils.tryDecrypt(KEY_ALIAS, Base64.decode(cipherText, Base64.DEFAULT));
        return new String(result);
    }

    @NonNull
    private String encryptToString(@NonNull String value) {
        byte[] result = Utils.tryEncrypt(KEY_ALIAS, value.getBytes());
        return Base64.encodeToString(result, Base64.DEFAULT);
    }
}
