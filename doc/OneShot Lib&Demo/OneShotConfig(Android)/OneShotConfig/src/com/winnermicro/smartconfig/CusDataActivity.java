package com.winnermicro.smartconfig;

import android.app.Activity;
import android.content.res.Configuration;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;

public class CusDataActivity extends Activity {

	private Button btnConf;
	private EditText editPsw;
	private boolean isStart;
	private String psw;
	private ISmartConfig smartConfig;
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_cus_data);
		
		btnConf = (Button)findViewById(R.id.btn_cus_data);
		btnConf.setOnClickListener(onButtonConfClick);
		editPsw = (EditText)findViewById(R.id.text_cus_data);
		SmartConfigFactory factory = new SmartConfigFactory();
		//通过修改参数ConfigType，确定使用何种方式进行一键配置，需要和固件侧保持一致。
		smartConfig = factory.createSmartConfig(ConfigType.UDP, this);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.cus_data, menu);
		return true;
	}
	@Override
	protected void onDestroy() {
		super.onDestroy();
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

			/*editPsw.setFilters(new InputFilter[] { new InputFilter() {
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

	private void stopConfig() {
		isStart = false;
		btnConf.setEnabled(false);
	}
	
	private OnClickListener onButtonConfClick = new OnClickListener(){

		@Override
		public void onClick(View v) {
			if(isStart){
				stopConfig();
				return;
			}
			psw = editPsw.getText().toString();
			isStart = true;
			setEditable(false);
			new Thread(new UDPReqThread()).start();
			btnConf.setText(getText(R.string.btn_stop_cus_data));
		}
	};

	private Runnable confPost = new Runnable(){

		@Override
		public void run() {
			isStart=false;
			btnConf.setEnabled(true);
			setEditable(true);
			btnConf.setText(getText(R.string.btn_cus_data));
		}
		
	};
	class UDPReqThread implements Runnable {
		public void run() {
			WifiManager wifiManager = null;
			try {
				wifiManager = (WifiManager) getSystemService(WIFI_SERVICE);  
				if(wifiManager.isWifiEnabled())
				{
					while(isStart){
						if(smartConfig.sendData(psw) == false)
						{
							break;
						}
						Thread.sleep(10);
					}
				}
			} 
			catch (Exception e) {
				e.printStackTrace();
			}
			finally{
				smartConfig.stopConfig();
				runOnUiThread(confPost);
			}
		}		
	}
}
