package com.cybex.basemodule.help;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

public class StoreLanguageHelper {

    public static void setLanguageLocal(Context context, String language){
        SharedPreferences preferences;
        SharedPreferences.Editor editor;
        preferences = PreferenceManager.getDefaultSharedPreferences(context);
        editor = preferences.edit();
        editor.putString("language", language);
        editor.apply();
    }

    public static String getLanguageLocal(Context context){
        SharedPreferences preferences;
        preferences = PreferenceManager.getDefaultSharedPreferences(context);
        String language = preferences.getString("language", "");
        return language;
    }

}
