# 2IMS30 Defence Design of HELLO/DIO Flooding Attack

**Group 6:  Groote Woortmann Arthur (arthurgrootewoortmann@gmail.com), Ruxandra Hristache (ruxi.hristache@yahoo.com), Chengqi Liu (chengqiliu946@gmail.com)**

This code uses the double sliding window method to detect the HELLO/DIO flooding attack. 

To run this detection, first export the pcapng format file captured by Wireshark into a csv file. Name the csv file "sensniff_result.csv" and put it in the same folder as the Python code, then run the code.

Commenting out lines 69 and 70 of the code can overlap the two bar charts, which may make the comparison results more intuitive.

Commenting out line 60 and uncommenting lines 56 to 59 will display the node names on the x-axis. This can only be used with two bars chart overlapped. However, this can result in the node names hard to read if there are too many DIO packages, and require zooming in to see them.

 



