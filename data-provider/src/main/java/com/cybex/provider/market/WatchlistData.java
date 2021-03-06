package com.cybex.provider.market;

import android.support.annotation.NonNull;

import com.cybex.provider.graphene.chain.AssetObject;
import com.cybex.provider.graphene.chain.AssetsPair;
import com.cybex.provider.graphene.chain.MarketTicker;
import com.cybex.provider.utils.PriceUtil;

import java.io.Serializable;
import java.util.List;

@SuppressWarnings("serial")
public class WatchlistData implements Serializable, Comparable<WatchlistData> {

    private AssetObject baseAsset;
    private AssetObject quoteAsset;
    private MarketTicker marketTicker;

    //最高价
    private double high;
    //最低价
    private double low;
    //base交易量
    private double baseVol;
    //quote交易量
    private double quoteVol;
    //base与quote的比例
    private double currentPrice;
    //base名称
    private String baseSymbol;
    //quote名称
    private String quoteSymbol;
    //涨跌幅
    private double change;
    //时间
    private long time;
    //base编号
    private String baseId;
    //quote编号
    private String quoteId;
    //订阅号
    private int subscribeId;
    //人名币价格
    private double rmbPrice;
    //quote人民币价格
    private double quoteRmbPrice;
    //base精度
    private int basePrecision;
    //quote精度
    private int quotePrecision;
    //排序
    private int order;
    //价格精度
    private int pricePrecision;
    //数量精度
    private int amountPrecision;
    //成交额精度
    private int totalPrecision;
    //人名币精度
    private int rmbPrecision;
    //24H成交量精度
    private int dayAmountPrecision;

    public WatchlistData() {

    }

    public WatchlistData(AssetObject baseAsset, AssetObject quoteAsset) {
        this.baseAsset = baseAsset;
        this.quoteAsset = quoteAsset;
        parseAsset(baseAsset, quoteAsset);
    }

    public WatchlistData(MarketTicker marketTicker) {
        this.marketTicker = marketTicker;
        parseMarketTicker(marketTicker);
    }

    public WatchlistData(long time, double high, double low, double baseVol, double quoteVol, double currentPrice, String baseSymbol, String quoteSymbol, double change, String baseId, String quoteId, int subscribeId, double rmbPrice, double quoteRmbPrice, int basePrecision, int quotePrecision) {
        this.high = high;
        this.low = low;
        this.baseVol = baseVol;
        this.quoteVol = quoteVol;
        this.time = time;
        this.currentPrice = currentPrice;
        this.baseSymbol = baseSymbol;
        this.quoteSymbol = quoteSymbol;
        this.change = change;
        this.baseId = baseId;
        this.quoteId = quoteId;
        this.subscribeId = subscribeId;
        this.rmbPrice = rmbPrice;
        this.quoteRmbPrice = quoteRmbPrice;
        this.basePrecision = basePrecision;
        this.quotePrecision = quotePrecision;
    }

    public double getHigh() {
        return high;
    }

    public void setHigh(double high) {
        this.high = high;
    }

    public double getLow() {
        return low;
    }

    public void setLow(double low) {
        this.low = low;
    }

    public double getBaseVol() {
        return baseVol;
    }

    public void setBaseVol(double baseVol) {
        this.baseVol = baseVol;
    }

    public double getQuoteVol() {
        return quoteVol;
    }

    public void setQuoteVol(double quoteVol) {
        this.quoteVol = quoteVol;
    }

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        this.time = time;
    }

    public double getCurrentPrice() {
        return this.currentPrice;
    }

    public void setCurrentPrice(double currentPrice) {
        this.currentPrice = currentPrice;
    }

    public double getChange() {
        return this.change;
    }

    public void setChange(double change) {
        this.change = change;
    }

    public String getBaseSymbol() {
        return this.baseSymbol;
    }

    public void setBaseSymbol(String baseSymbol) {
        this.baseSymbol = baseSymbol;
    }

    public String getQuoteSymbol() {
        return this.quoteSymbol;
    }

    public void setQuoteSymbol(String quoteSymbol) {
        this.quoteSymbol = quoteSymbol;
    }

    public String getBaseId() {
        return baseId;
    }

    public void setBaseId(String baseId) {
        this.baseId = baseId;
    }

    public String getQuoteId() {
        return quoteId;
    }

    public void setQuoteId(String quoteId) {
        this.quoteId = quoteId;
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        this.order = order;
    }

    public void setSubscribeId(int subscribeId) {
        this.subscribeId = subscribeId;
    }

    public int getSubscribeId() {
        return subscribeId;
    }

    public double getRmbPrice() {
        return rmbPrice;
    }

    public void setRmbPrice(double rmbPrice) {
        this.rmbPrice = rmbPrice;
    }

    public double getQuoteRmbPrice() {
        return quoteRmbPrice;
    }

    public void setQuoteRmbPrice(double quoteRmbPrice) {
        this.quoteRmbPrice = quoteRmbPrice;
    }

    public int getBasePrecision() {
        return basePrecision;
    }

    public void setBasePrecision(int basePrecision) {
        this.basePrecision = basePrecision;
    }

    public int getQuotePrecision() {
        return quotePrecision;
    }

    public void setQuotePrecision(int quotePrecision) {
        this.quotePrecision = quotePrecision;
    }

    public int getPricePrecision() {
        return pricePrecision;
    }

    public void setPricePrecision(int pricePrecision) {
        this.pricePrecision = pricePrecision;
    }

    public int getAmountPrecision() {
        return amountPrecision;
    }

    public void setAmountPrecision(int amountPrecision) {
        this.amountPrecision = amountPrecision;
    }

    public int getTotalPrecision() {
        return totalPrecision;
    }

    public void setTotalPrecision(int totalPrecision) {
        this.totalPrecision = totalPrecision;
    }

    public int getRmbPrecision() {
        return rmbPrecision;
    }

    public void setRmbPrecision(int rmbPrecision) {
        this.rmbPrecision = rmbPrecision;
    }

    public int getDayAmountPrecision() {
        return dayAmountPrecision;
    }

    public void setDayAmountPrecision(int dayAmountPrecision) {
        this.dayAmountPrecision = dayAmountPrecision;
    }

    public void setAssetPairConfig(AssetsPair.Config assetPairConfig) {
        this.rmbPrecision = 4;
        this.dayAmountPrecision = 2;
        this.pricePrecision = Integer.parseInt(assetPairConfig.last_price);
        this.amountPrecision = Integer.parseInt(assetPairConfig.amount);
        this.totalPrecision = Integer.parseInt(assetPairConfig.total);
    }

    public AssetObject getBaseAsset() {
        return baseAsset;
    }

    public void setBaseAsset(AssetObject baseAsset) {
        this.baseAsset = baseAsset;
        parseBaseAsset(baseAsset);
    }

    public AssetObject getQuoteAsset() {
        return quoteAsset;
    }

    public void setQuoteAsset(AssetObject quoteAsset) {
        this.quoteAsset = quoteAsset;
        parseQuoteAsset(quoteAsset);
    }

    public MarketTicker getMarketTicker() {
        return marketTicker;
    }

    public void setMarketTicker(MarketTicker marketTicker) {
        this.marketTicker = marketTicker;
        parseMarketTicker(marketTicker);
    }

    private void parseBaseAsset(AssetObject baseAsset) {
        if (baseAsset == null) {
            return;
        }
        this.baseId = baseAsset.id.toString();
        this.baseSymbol = baseAsset.symbol;
        this.basePrecision = baseAsset.precision;
    }

    private void parseQuoteAsset(AssetObject quoteAsset) {
        if (quoteAsset == null) {
            return;
        }
        this.quoteId = quoteAsset.id.toString();
        this.quoteSymbol = quoteAsset.symbol;
        this.quotePrecision = quoteAsset.precision;
    }

    private void parseAsset(AssetObject baseAsset, AssetObject quoteAsset) {
        parseBaseAsset(baseAsset);
        parseQuoteAsset(quoteAsset);
    }

    private void parseMarketTicker(MarketTicker marketTicker) {
        if (marketTicker == null) {
            return;
        }
        this.baseVol = marketTicker.base_volume;
        this.quoteVol = marketTicker.quote_volume;
        this.high = marketTicker.highest_bid;
        this.low = marketTicker.lowest_ask;
        this.currentPrice = marketTicker.latest;
        this.change = marketTicker.percent_change;
    }

    @Override
    public int compareTo(@NonNull WatchlistData o) {
        if(o.getOrder() == 0 && this.getOrder() == 0){
            return this.getBaseVol() > o.getBaseVol() ? -1 : 1;
        }
        return this.getOrder() > o.getOrder() ? -1 : 1;
    }

}
