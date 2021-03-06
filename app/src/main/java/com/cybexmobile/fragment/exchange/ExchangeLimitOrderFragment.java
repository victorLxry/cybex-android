package com.cybexmobile.fragment.exchange;

import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.cybex.basemodule.base.BaseFragment;
import com.cybex.provider.market.WatchlistData;
import com.cybexmobile.R;
import com.cybexmobile.adapter.BuySellOrderRecyclerViewAdapter;
import com.cybex.provider.http.entity.AssetRmbPrice;
import com.cybex.basemodule.event.Event;
import com.cybex.basemodule.utils.AssetUtil;
import com.jaredrummler.materialspinner.MaterialSpinner;

import org.greenrobot.eventbus.EventBus;
import org.greenrobot.eventbus.Subscribe;
import org.greenrobot.eventbus.ThreadMode;

import java.util.ArrayList;
import java.util.List;

import butterknife.BindString;
import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;
import butterknife.Unbinder;

import static com.cybex.basemodule.constant.Constant.BUNDLE_SAVE_PRECISION;
import static com.cybex.basemodule.constant.Constant.BUNDLE_SAVE_SPINNER_POSITION;
import static com.cybex.basemodule.constant.Constant.BUNDLE_SAVE_WATCHLIST;
import static com.cybex.basemodule.constant.Constant.INTENT_PARAM_PRECISION;
import static com.cybex.basemodule.constant.Constant.INTENT_PARAM_SPINNER_POSITION;
import static com.cybex.basemodule.constant.Constant.INTENT_PARAM_WATCHLIST;

/**
 * 交易界面所有用户当前交易对委单
 */
public class ExchangeLimitOrderFragment extends BaseFragment implements BuySellOrderRecyclerViewAdapter.OnItemClickListener{

    @BindView(R.id.buysell_rv_sell)
    RecyclerView mRvSell;
    @BindView(R.id.buysell_rv_buy)
    RecyclerView mRvBuy;

    @BindView(R.id.buysell_tv_order_price)
    TextView mTvOrderPrice;
    @BindView(R.id.buysell_tv_order_amount)
    TextView mTvOrderAmount;
    @BindView(R.id.buysell_tv_quote_price)
    TextView mTvQuotePrice;
    @BindView(R.id.buysell_tv_quote_rmb_price)
    TextView mTvQuoteRmbPrice;
    @BindView(R.id.buysell_sp_precision)
    MaterialSpinner mMaterialSpinner;
    @BindString(R.string.text_decimals)
    String mTextDecimals;

    private List<List<String>> mBuyOrders = new ArrayList<>();
    private List<List<String>> mSellOrders = new ArrayList<>();

    private BuySellOrderRecyclerViewAdapter mBuyOrderAdapter;
    private BuySellOrderRecyclerViewAdapter mSellOrderAdapter;

    private Unbinder mUnbinder;

    private WatchlistData mWatchlistData;
    //交易对价格
    private double mMarketPrice;

    private int mPrecision;
    private int mSpinnerPosition;

    public static ExchangeLimitOrderFragment getInstance(WatchlistData watchlistData, int precision, int position){
        ExchangeLimitOrderFragment fragment = new ExchangeLimitOrderFragment();
        Bundle bundle = new Bundle();
        bundle.putSerializable(INTENT_PARAM_WATCHLIST, watchlistData);
        bundle.putInt(INTENT_PARAM_PRECISION, precision);
        bundle.putInt(INTENT_PARAM_SPINNER_POSITION, position);
        fragment.setArguments(bundle);
        return fragment;
    }

    @Override
    public void onAttachFragment(Fragment childFragment) {
        super.onAttachFragment(childFragment);
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
        Bundle bundle = getArguments();
        if(bundle != null){
            mWatchlistData = (WatchlistData) bundle.getSerializable(INTENT_PARAM_WATCHLIST);
            mPrecision = bundle.getInt(INTENT_PARAM_PRECISION, -1);
            mSpinnerPosition = bundle.getInt(INTENT_PARAM_SPINNER_POSITION, 0);
        }
        if(savedInstanceState != null){
            mWatchlistData = (WatchlistData) savedInstanceState.getSerializable(BUNDLE_SAVE_WATCHLIST);
            mPrecision = savedInstanceState.getInt(BUNDLE_SAVE_PRECISION, -1);
            mSpinnerPosition = savedInstanceState.getInt(BUNDLE_SAVE_SPINNER_POSITION, 0);
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_exchange_limit_order, container, false);
        mUnbinder = ButterKnife.bind(this, view);
        mRvSell.setLayoutManager(new LinearLayoutManager(getContext()));
        mRvBuy.setLayoutManager(new LinearLayoutManager(getContext()));
        mBuyOrderAdapter = new BuySellOrderRecyclerViewAdapter(getContext(), mWatchlistData, BuySellOrderRecyclerViewAdapter.TYPE_BUY, mBuyOrders);
        mSellOrderAdapter = new BuySellOrderRecyclerViewAdapter(getContext(), mWatchlistData, BuySellOrderRecyclerViewAdapter.TYPE_SELL, mSellOrders);
        mBuyOrderAdapter.setPricePrecision(mPrecision);
        mSellOrderAdapter.setPricePrecision(mPrecision);
        mBuyOrderAdapter.setOnItemClickListener(this);
        mSellOrderAdapter.setOnItemClickListener(this);
        mRvBuy.setAdapter(mBuyOrderAdapter);
        mRvSell.setAdapter(mSellOrderAdapter);
        mMaterialSpinner.setOnItemSelectedListener(new MaterialSpinner.OnItemSelectedListener<String>() {
            @Override
            public void onItemSelected(MaterialSpinner view, int position, long id, String item) {
                mSpinnerPosition = position;
                int precision = Integer.parseInt(item.substring(0, 1));
                mPrecision = precision;
                mBuyOrderAdapter.setPricePrecision(precision);
                mSellOrderAdapter.setPricePrecision(precision);
                ((ExchangeFragment)getParentFragment().getParentFragment()).reSubscribeOrderBook(precision, position);
            }
        });
        return view;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        initViewData(true);
    }

    @Override
    public void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putSerializable(BUNDLE_SAVE_WATCHLIST, mWatchlistData);
        outState.putInt(BUNDLE_SAVE_PRECISION, mPrecision);
        outState.putInt(BUNDLE_SAVE_SPINNER_POSITION, mSpinnerPosition);
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        mUnbinder.unbind();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }

    @Subscribe(threadMode = ThreadMode.MAIN)
    public void onUpdateWatchlist(Event.UpdateWatchlist event) {
        WatchlistData data = event.getData();
        if(data == null || mWatchlistData == null){
            return;
        }
        if(data.getBaseId().equals(mWatchlistData.getBaseId()) && data.getQuoteId().equals(mWatchlistData.getQuoteId())){
            mWatchlistData = data;
        }
    }

    @Subscribe(threadMode = ThreadMode.MAIN)
    public void onUpdateRmbPrice(Event.UpdateRmbPrice event) {
        if(mWatchlistData == null){
            return;
        }
        List<AssetRmbPrice> assetRmbPrices = event.getData();
        if (assetRmbPrices == null || assetRmbPrices.size() == 0) {
            return;
        }
        AssetRmbPrice assetRmbPrice = null;
        for (AssetRmbPrice rmbPrice : assetRmbPrices) {
            if (mWatchlistData.getBaseSymbol().contains(rmbPrice.getName())) {
                assetRmbPrice = rmbPrice;
                break;
            }
        }
        if (assetRmbPrice == null) {
            return;
        }
        mWatchlistData.setRmbPrice(assetRmbPrice.getValue());
        initOrResetRmbPrice();
    }

    @Override
    public void onNetWorkStateChanged(boolean isAvailable) {

    }

    @Override
    public void onItemClick(String price) {
        EventBus.getDefault().post(new Event.LimitOrderClick(price));
    }

    @OnClick({R.id.buysell_tv_quote_price, R.id.buysell_tv_quote_rmb_price})
    public void onQuotePriceClick(View view){
        if(mWatchlistData == null || mWatchlistData.getCurrentPrice() == 0){
            return;
        }
        EventBus.getDefault().post(new Event.LimitOrderClick(mTvQuotePrice.getText().toString()));
    }

    private void initViewData(boolean isInit){
        if(mWatchlistData == null){
            return;
        }
        initOrResetSpinnerData();
        if (isInit) {
            mMaterialSpinner.setSelectedIndex(mSpinnerPosition);
        }
        String baseSymbol = AssetUtil.parseSymbol(mWatchlistData.getBaseSymbol());
        String quoteSymbol = AssetUtil.parseSymbol(mWatchlistData.getQuoteSymbol());
        mTvOrderPrice.setText(getResources().getString(R.string.text_asset_price).replace("--", baseSymbol));
        mTvOrderAmount.setText(getResources().getString(R.string.text_asset_amount).replace("--", quoteSymbol));
    }

    private void initOrResetSpinnerData() {
        List<String> items = new ArrayList<>();
        int precision = mWatchlistData.getPricePrecision();
        while (items.size() < 4 && precision >= 0) {
            items.add(precision + " " + mTextDecimals);
            --precision;
        }
        mMaterialSpinner.notifyItems(items);
    }

    private void initOrResetPrice(double price) {
        if(price == mMarketPrice) {
            mTvQuotePrice.setTextColor(getResources().getColor(R.color.no_change_color));
            mTvQuoteRmbPrice.setTextColor(getResources().getColor(R.color.no_change_color));
        } else if(price > mMarketPrice){
            mTvQuotePrice.setTextColor(getResources().getColor(R.color.increasing_color));
            mTvQuoteRmbPrice.setTextColor(getResources().getColor(R.color.increasing_color));
        } else {
            mTvQuotePrice.setTextColor(getResources().getColor(R.color.decreasing_color));
            mTvQuoteRmbPrice.setTextColor(getResources().getColor(R.color.decreasing_color));
        }
        mMarketPrice = price;
        mTvQuotePrice.setText(mMarketPrice == 0 ? getString(R.string.text_empty) : AssetUtil.formatNumberRounding(mMarketPrice, mWatchlistData.getPricePrecision()));
        initOrResetRmbPrice();
    }

    private void initOrResetRmbPrice() {
        double marketPrice = Double.parseDouble(AssetUtil.formatNumberRounding(mMarketPrice, mWatchlistData.getPricePrecision()));
        mTvQuoteRmbPrice.setText(String.format("≈¥%s", mMarketPrice == 0 ? getString(R.string.text_empty) :
                AssetUtil.formatNumberRounding(marketPrice * mWatchlistData.getRmbPrice(), mWatchlistData.getRmbPrecision())));
    }

    public void changeWatchlist(WatchlistData watchlist){
        this.mWatchlistData = watchlist;
        initOrResetPrice(0);
        mBuyOrderAdapter.setWatchlistData(mWatchlistData);
        mSellOrderAdapter.setWatchlistData(mWatchlistData);
        initViewData(false);
        mBuyOrderAdapter.setPricePrecision(-1);
        mSellOrderAdapter.setPricePrecision(-1);
        mBuyOrders.clear();
        mSellOrders.clear();
        mBuyOrderAdapter.notifyDataSetChanged();
        mSellOrderAdapter.notifyDataSetChanged();
    }

    public void notifyPrecisionChanged(int precision, int position) {
        mPrecision = precision;
        mSpinnerPosition = position;
        mBuyOrderAdapter.setPricePrecision(precision);
        mSellOrderAdapter.setPricePrecision(precision);
        mMaterialSpinner.setSelectedIndex(position);
    }

    public void notifyLimitOrderDataChanged(List<List<String>> sellOrders, List<List<String>> buyOrders) {
        mBuyOrders.clear();
        mSellOrders.clear();
        mBuyOrders.addAll(buyOrders);
        mSellOrders.addAll(sellOrders);
        mBuyOrderAdapter.notifyDataSetChanged();
        mSellOrderAdapter.notifyDataSetChanged();
    }

    public void notifyMarketPriceDataChanged(double price) {
        initOrResetPrice(price);
    }
}
