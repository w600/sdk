package com.winnermicro.smartconfig;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.res.Configuration;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

public class OneShotActivity extends Activity {

	public static final int TYPE_NO_PASSWD = 0x11;
	public static final int TYPE_WEP = 0x12;
	public static final int TYPE_WPA = 0x13;
	    
	private Button btnConf;
	private TextView textSsid;
	private TextView text_total;
	private EditText editPsw;
	private boolean isStart = false;
	private String ssid;
	private String psw = null;
	private IOneShotConfig oneshotConfig = null;
	private Boolean isThreadDisable = false;//指示监听线程是否终止
	private List<String> lstMac = new ArrayList<String>();
	private UdpHelper udphelper;
	private Thread tReceived;
	private ListView listView;
	private ResultAdapter adapter = null;
	private SmartConfigFactory factory = null;
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_one_shot);
		btnConf = (Button)findViewById(R.id.btn_conf);
		btnConf.setOnClickListener(onButtonConfClick);
		textSsid = (TextView)findViewById(R.id.text_ssid);
		text_total = (TextView) findViewById(R.id.text_total);
		
		editPsw = (EditText) findViewById(R.id.text_psw);
		listView = (ListView) findViewById(R.id.listView1);
		
        
		factory = new SmartConfigFactory();
		//通过修改参数ConfigType，确定使用何种方式进行一键配置，需要和固件侧保持一致。
		oneshotConfig = factory.createOneShotConfig(ConfigType.UDP);
		editPsw.requestFocus();
	}
	
	@Override
	protected void onStop() {
		super.onStop();
		stopConfig();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.one_shot, menu);
		return true;
	}
	
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {

		case R.id.action_custom:

			// 在action bar点击app icon; 回到 home

			Intent intent = new Intent(this, CusDataActivity.class);

			intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);

			startActivity(intent);

			return true;
		case R.id.action_get_ver:
			String ver = factory.getVersion();
			Toast.makeText(this, "SDK ver " + ver, Toast.LENGTH_SHORT).show();
			break;
		default:
			break;
		}
		return super.onOptionsItemSelected(item);
	}
	
	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
		if(keyCode == KeyEvent.KEYCODE_BACK) {
			if(isStart){
				stopConfig();
			}
		}
		return super.onKeyDown(keyCode, event);
	}
	private void setEditable(boolean value) {
		if (value) {
			/*editPsw.setFilters(new InputFilter[] { new InputFilter() {
				public CharSequence filter(CharSequence source, int start,
						int end, Spanned dest, int dstart, int dend) {
					return null;
				}
			} });*/
			editPsw.setCursorVisible(true);
			editPsw.setFocusable(true);     
			editPsw.setFocusableInTouchMode(true);
			editPsw.requestFocus();
		} else {
			/*
			editPsw.setFilters(new InputFilter[] { new InputFilter() {
				@Override
				public CharSequence filter(CharSequence source, int start,
						int end, Spanned dest, int dstart, int dend) {
					return source.length() < 1 ? dest.subSequence(dstart, dend)
							: "";
				}

			} });*/
			editPsw.setCursorVisible(false);
			editPsw.setFocusable(false);  
			editPsw.setFocusableInTouchMode(false);
			editPsw.clearFocus();
		}
	}
	private void stopConfig(){
		isThreadDisable = true;
		if(isStart){
			isStart = false;
			btnConf.setEnabled(false);
		}
		oneshotConfig.stop();
	}
	/**
	 * 
	 * 
	 * 
	 * 当设备配置信息有改动（比如屏幕方向的改变，实体键盘的推开或合上等）时，
	 * 
	 * 并且如果此时有activity正在运行，系统会调用这个函数。
	 * 
	 * 注意：onConfigurationChanged只会监测应用程序在AnroidMainifest.xml中通过
	 * 
	 * android:configChanges="xxxx"指定的配置类型的改动；
	 * 
	 * 而对于其他配置的更改，则系统会onDestroy()当前Activity，然后重启一个新的Activity实例。
	 */

	@Override
	public void onConfigurationChanged(Configuration newConfig) {

		super.onConfigurationChanged(newConfig);

		// 检测屏幕的方向：纵向或横向

		if (this.getResources().getConfiguration().orientation

		== Configuration.ORIENTATION_LANDSCAPE) {

			// 当前为横屏， 在此处添加额外的处理代码

		} else if (this.getResources().getConfiguration().orientation == Configuration.ORIENTATION_PORTRAIT) {

			// 当前为竖屏， 在此处添加额外的处理代码

		}

		// 检测实体键盘的状态：推出或者合上

		if (newConfig.hardKeyboardHidden

		== Configuration.HARDKEYBOARDHIDDEN_NO) {

			// 实体键盘处于推出状态，在此处添加额外的处理代码
		} else if (newConfig.hardKeyboardHidden == Configuration.HARDKEYBOARDHIDDEN_YES) {
			// 实体键盘处于合上状态，在此处添加额外的处理代码
		}
	}
	
	/**判断热点开启状态*/
	public boolean isWifiApEnabled() {
		return getWifiApState() == WIFI_AP_STATE.WIFI_AP_STATE_ENABLED;
	}

	private WIFI_AP_STATE getWifiApState(){
		int tmp;
		WifiManager wifiManager = (WifiManager) getSystemService(WIFI_SERVICE);
		try {
			Method method = wifiManager.getClass().getMethod("getWifiApState");
			tmp = ((Integer) method.invoke(wifiManager));
			// Fix for Android 4
			if (tmp > 10) {
				tmp = tmp - 10;
			}
			return WIFI_AP_STATE.class.getEnumConstants()[tmp];
		} catch (Exception e) {
			e.printStackTrace();
			return WIFI_AP_STATE.WIFI_AP_STATE_FAILED;
		}
	}
	
	public enum WIFI_AP_STATE {
		WIFI_AP_STATE_DISABLING, WIFI_AP_STATE_DISABLED, WIFI_AP_STATE_ENABLING,  WIFI_AP_STATE_ENABLED, WIFI_AP_STATE_FAILED
	}
	
	@Override
	protected void onStart()
	{
		super.onStart();
		try {
			WifiManager wifiManager = (WifiManager) getSystemService(WIFI_SERVICE);  
			if(wifiManager.isWifiEnabled())
			{
				WifiInfo wifiInfo = wifiManager.getConnectionInfo();
				String ssidString = null;
				if (wifiInfo != null) {
					ssidString = wifiInfo.getSSID();
					int version = getAndroidSDKVersion();
					if (version > 16 && ssidString.startsWith("\"") && ssidString.endsWith("\"")) {
						ssidString = ssidString.substring(1, ssidString.length() - 1);
					}
				}
				this.textSsid.setText(ssidString);
			}
			else if(isWifiApEnabled())
			{
				WifiConfiguration conf = getWifiApConfiguration();
				String ssidString=null;
				if(conf != null){
					ssidString = conf.SSID;
				}
				this.textSsid.setText(ssidString);
			}
			else
			{
				displayToast("网络不可用，请检查网络!");
			}
			adapter = new ResultAdapter(this, android.R.layout.simple_expandable_list_item_1, lstMac);
			listView.setAdapter(adapter);
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}
	@Override
	protected void onDestroy() {
		super.onDestroy();
	}
	public void displayToast(String str)
	{
		Toast.makeText(this, str, Toast.LENGTH_SHORT).show();
	}

	private WifiConfiguration getWifiApConfiguration(){
		WifiManager wifiManager = (WifiManager) getSystemService(WIFI_SERVICE);
		try {
			Method method = wifiManager.getClass().getMethod("getWifiApConfiguration");
			WifiConfiguration tmp = ((WifiConfiguration) method.invoke(wifiManager));
			
			return tmp;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	private int getAndroidSDKVersion() { 
		int version = 0;
		try {
			version = Integer.valueOf(android.os.Build.VERSION.SDK_INT);
		} catch (NumberFormatException e) {
			Log.e(e.toString(), e.getMessage());
		}
		return version;
	}
	private OnClickListener onButtonConfClick = new OnClickListener(){

		@Override
		public void onClick(View v) {
			if(isStart){
				stopConfig();
				return;
			}
			/*String ssid = mySpinner.getSelectedItem().toString();
			if(ssid.length() == 0){
				displayToast("请先连接WIFI网络!");
				return;
			}*/
			ssid = textSsid.getText().toString();
			psw = editPsw.getText().toString();
			lstMac.clear();
			adapter.notifyDataSetChanged();
			isStart = true;
			isThreadDisable = false;
			setEditable(false);
			WifiManager wifiManager = (WifiManager) getSystemService(WIFI_SERVICE);
			udphelper = new UdpHelper(wifiManager);
			tReceived = new Thread(udphelper);
	        tReceived.start();
			new Thread(new UDPReqThread()).start();
			text_total.setText(String.format("%d connected.", lstMac.size()));
			btnConf.setText(getText(R.string.btn_stop_conf));
		}
	};
	
	private Runnable confPost = new Runnable(){
		
		@Override
		public void run() {
			isStart=false;
			isThreadDisable = true;
			btnConf.setEnabled(true);
			setEditable(true);
			btnConf.setText(getText(R.string.btn_conf));
			if(adapter != null){
				adapter.notifyDataSetChanged();
			}	
		}
		
	};
	
	private Runnable notifyPost = new Runnable(){
		
		@Override
		public void run() {
			if(adapter != null){
				adapter.notifyDataSetChanged();
			}
			text_total.setText(String.format("%d connected.", lstMac.size()));
			//Toast.makeText(getApplicationContext(), String.format("%d connected.", lstMac.size()),
			//		Toast.LENGTH_SHORT).show();
		}
		
	};
	class UDPReqThread implements Runnable {
		public void run() {
			WifiManager wifiManager = null;
			try {
				wifiManager = (WifiManager) getSystemService(WIFI_SERVICE);  
				if(wifiManager.isWifiEnabled() || isWifiApEnabled())
				{
					int timeout = 60;//miao
					oneshotConfig.start(ssid, psw, timeout, OneShotActivity.this);
				}
			}
			catch (Exception e) {
				e.printStackTrace();
			}
			finally{
				oneshotConfig.stop(	);
				runOnUiThread(confPost);
			}
		}
	}
	
	@SuppressLint("DefaultLocale")
	class UdpHelper implements Runnable {

	    private WifiManager.MulticastLock lock;
	    InetAddress mInetAddress;
	    public UdpHelper(WifiManager manager) {
	         this.lock= manager.createMulticastLock("UDPwifi"); 
	    }
	    public void StartListen()  {
	        // UDP服务器监听的端口
	        Integer port = 65534;
	        // 接收的字节大小，客户端发送的数据不能超过这个大小
	        byte[] message = new byte[100];
	        try {
	            // 建立Socket连接
	            DatagramSocket datagramSocket = new DatagramSocket(port);
	            datagramSocket.setBroadcast(true);
	            datagramSocket.setSoTimeout(1000);
	            DatagramPacket datagramPacket = new DatagramPacket(message,
	                    message.length);
	            try {
	                while (!isThreadDisable) {
	                    // 准备接收数据
	                    Log.d("UDP Demo", "准备接受");
	                    this.lock.acquire();
	                    try{
		                    datagramSocket.receive(datagramPacket);
		                    String strMsg="";
		                    int count = datagramPacket.getLength();
		                    for(int i=0;i<count;i++){
		                    	strMsg += String.format("%02x", datagramPacket.getData()[i]);
		                    }
		                    strMsg = strMsg.toUpperCase() + ";" + datagramPacket.getAddress().getHostAddress().toString();
		                    if(!lstMac.contains(strMsg)){
		                    	lstMac.add(strMsg);
		                    	runOnUiThread(notifyPost);
		                    }
		                    Log.d("UDP Demo", datagramPacket.getAddress()
		                            .getHostAddress().toString()
		                            + ":" +strMsg );
		                    }
	                    catch(SocketTimeoutException ex){
	                    	Log.d("UDP Demo", "UDP Receive Timeout.");
	                    }
	                    this.lock.release();
	                }
	            } catch (IOException e) {//IOException
	                e.printStackTrace();
	            }
	            datagramSocket.close();
	        } catch (SocketException e) {
	            e.printStackTrace();
	        }
	        finally{
	        	if(!isThreadDisable){
	        		runOnUiThread(confPost);
	        	}
	        }
	    }
		@Override
		public void run() {
			StartListen();
		}

	}
}
