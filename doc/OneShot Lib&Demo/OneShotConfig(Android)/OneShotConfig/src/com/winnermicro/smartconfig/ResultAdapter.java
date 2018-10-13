package com.winnermicro.smartconfig;

import java.util.List;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

@SuppressWarnings("rawtypes")
public class ResultAdapter extends ArrayAdapter {
	private LayoutInflater layoutInflater = null;
    private List<String> lstMac;
    
	@SuppressWarnings({ "unchecked" })
	public ResultAdapter(Context context, int resource, List objects) {
		super(context, resource, objects);
		layoutInflater = LayoutInflater.from(context);
		lstMac = objects;
	}
	@Override
    public int getCount() {
        return lstMac.size();
    }

    @Override
    public Object getItem(int position) {
        return lstMac.get(position);
    }
    
    @Override
    public long getItemId(int position) {
        return position;
    } 
	@Override
	public View getView(int position, View convertView, ViewGroup parent) {
		ViewHolder holder;
        if(convertView == null){
            convertView = layoutInflater.inflate(R.layout.list_view, null);
            holder = new ViewHolder();
            holder.id = (TextView)convertView.findViewById(R.id.list_id);
            holder.mac = (TextView)convertView.findViewById(R.id.list_mac);
            holder.ip = (TextView)convertView.findViewById(R.id.list_ip);
            convertView.setTag(holder);
        }else{
            holder = (ViewHolder)convertView.getTag();
        }
        String str = lstMac.get(position);
        String[] strs = str.split(";");
        holder.id.setText(position+1+"");
        holder.mac.setText(strs[0]);
        holder.ip.setText(strs[1]);
        return convertView;
	}
	
	private static class ViewHolder {
		private TextView id;
		private TextView mac;
		private TextView ip;
	}
}
