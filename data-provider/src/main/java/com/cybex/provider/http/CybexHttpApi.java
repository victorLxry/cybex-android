package com.cybex.provider.http;

import com.cybex.provider.http.entity.AppVersion;
import com.cybex.provider.http.response.AppConfigResponse;
import com.cybex.provider.http.response.AssetsPairResponse;
import com.cybex.provider.http.response.AssetsPairToppingResponse;
import com.cybex.provider.http.response.CnyResponse;
import com.google.gson.JsonObject;

import java.util.List;

import io.reactivex.Flowable;
import io.reactivex.Observable;
import okhttp3.ResponseBody;
import retrofit2.http.GET;
import retrofit2.http.Path;
import retrofit2.http.Query;

public interface CybexHttpApi {

    @GET("price")
    Flowable<CnyResponse> getCny();

    @GET("Android_update.json")
    Observable<AppVersion> checkAppUpdate();

    @GET("Android_store_update.json")
    Observable<AppVersion> checkAppUpdateGoogleStore();

    @GET("/json/withdraw.json")
    Observable<ResponseBody> getWithdrawList();

    @GET("/json/deposit.json")
    Observable<ResponseBody> getDepositList();

    @GET("/json/deposit/{id}")
    Observable<ResponseBody> getDepositDetails(@Path("id") String path);

    @GET("/json/withdraw/{id}")
    Observable<ResponseBody> getWithdrawDetails(@Path("id") String path);

    @GET("market_list")
    Observable<AssetsPairResponse> getAssetsPair(@Query("base") String base);

    @GET("json/marketlists.json")
    Observable<List<AssetsPairToppingResponse>> getAssetsPairTopping();

    @GET("json/settings.json")
    Observable<AppConfigResponse> getSettingConfig();

    @GET("json/blockexplorer.json")
    Observable<ResponseBody> getBlockExplorerLink();

    @GET("json/assets.json")
    Observable<List<String>> getAssetWhiteList();

    @GET("json/pairs.json")
    Observable<JsonObject> getAssetPairsConfig();

    @GET("json/evaluape.json")
    Observable<JsonObject> getEvaProjectNames();

    @GET("json/validticket.json")
    Observable<JsonObject> getValidTickets();
}
