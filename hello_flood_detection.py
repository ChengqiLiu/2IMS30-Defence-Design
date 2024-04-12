import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import datetime

def time_in_range(time_1,time_2,range_=0):
    """
    Determine whether time_2-time_1 is less or euqal than the time range_ (in seconds).
    time_1 and time_2 are two time strings in format "%Y-%m-%d %H:%M:%S,%f".
    """
    date_format=r"%Y-%m-%d %H:%M:%S,%f"
    t1=datetime.datetime.strptime(time_1,date_format)
    t2=datetime.datetime.strptime(time_2,date_format)
    if (t2-t1).total_seconds() <= range_:
        return True
    return False

def set_window_value(data,col_name,window_size):
    """
    Create a new column on the far right side.
    Set values at the column col_name for the sliding window algorithm with a given size window_size.
    """
    data.insert(data.shape[1], col_name, 0)
    for index in range(data.shape[0]):
        num=1
        for i in range(index,data.shape[0]):
            if time_in_range(data.loc[index,"Time"],data.loc[i,"Time"],window_size)\
                and data.loc[i,"Source"]==data.loc[index,"Source"]:
                num=num+1
            if not time_in_range(data.loc[index,"Time"],data.loc[i,"Time"],window_size):
                break
        data.loc[index,col_name]=num

Nodes={
    "Border":"fe80::212:4b00:173d:8a03",\
    "Node_1":"fe80::212:4b00:1204:d199",\
    "Node_2":"fe80::212:4b00:c46:c300",\
    "Node_3":"fe80::212:4b00:1665:2a04"
    }

def node_ip_to_name(ip):
    """ Change node IPv6 address to its name. """
    for (k,v) in Nodes.items():
        if v==ip:
            return k
    return ""

def plot_windows_data(data,t_long_window,t_short_window):
    """
    Plot the values in the two sliding windows of each packet. 
    The image will be very compact. Please enlarge to view.
    """
    y1=data["Long_window"].values
    y2=data["Short_window"].values

    # x=data["Source"].values                       # Plot node name on x-axis.
    # for i in range(data.shape[0]):
    #     x[i]=node_ip_to_name(x[i])
    #     x[i]=str(i)+", "+x[i]         
    x=np.arange(data.shape[0],dtype=np.float32)     # Plot only serial number on x-axis.

    total_width, n=0.6, 2
    width=total_width/n
    plt.figure(figsize=(24, 6))
    plt.title("Results of Intrusion Detection",fontsize="large")
    plt.xlabel("Serial Number of DIO Packet") 
    plt.ylabel("Number of DIO Packets in the Sliding Window") 
    plt.bar(x, y1,  width=width, label="in the window of "+str(t_long_window)+'s')
    for i in range(len(x)):                         # Make the two bar charts not overlapped.
        x[i]=x[i]+width
    plt.bar(x, y2, width=width, label="in the window of "+str(t_short_window)+'s')
    # plt.xticks([])  # Hide the ticks of the x-axis.
    plt.legend()
    plt.show()

def hello_flood_detection(data,t_long_window,t_short_window,threshold):
    """
    Use double sliding-window method to detect Hello Flood Attack.
    The sizes of the long and short sliding windows are t_long_window and t_short_window.
    The threshold measures the sending DIO frequency during the short sliding window compared to the long one.
    If this threshold is exceeded, it will be recorded as one suspicious behavior.
    """
    set_window_value(data,"Long_window",t_long_window)
    set_window_value(data,"Short_window",t_short_window)

    # Calculate the total number of suspicious behaviors detected for each node.
    malicios_n=dict()   # Stores the result of each node.
    for i in range(data.shape[0]):
        ratio=t_short_window/t_long_window
        if data.loc[i,"Short_window"]>threshold*ratio*data.loc[i,"Long_window"]:
            if data.loc[i,"Source"] not in malicios_n.keys():
                malicios_n[data.loc[i,"Source"]]=1
            else:
                malicios_n[data.loc[i,"Source"]]=malicios_n[data.loc[i,"Source"]]+1

    #Report the node with the highest number of suspicious behaviors.
    max_detected_num=0
    malicious_ip=""
    for (k,v) in malicios_n.items():
        if v>max_detected_num:
            max_detected_num=v
            malicious_ip=k

    print("Hello Flood Attack detected from IP",malicious_ip)
    print("Number of suspicious behaviors:",max_detected_num)


if __name__=="__main__":
    # Load data.
    data = pd.read_csv(
        r"./sensniff_result.csv",
        usecols=["Time","Source", "Info"],
        engine="c"
    )

    # Get the rows of DIO packets.
    data=data[data["Info"].isin(["RPL Control (DODAG Information Object)"])]
    data.reset_index(drop=True, inplace=True)

    t_long_window=20    # window size (seconds) for long sliding window
    t_short_window=2    # window size (seconds) for short sliding window
    threshold=6         # The larger threshold means the stricter testing.

    hello_flood_detection(data,t_long_window,t_short_window,threshold)
    #  Plot the number of DIO packets in windows by each DIO packet.
    plot_windows_data(data,t_long_window,t_short_window)