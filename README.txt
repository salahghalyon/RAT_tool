This README file is to accompany code for analyzing several threats on robotic platforms,
produced by Khalil M. Ahmad Yousef, Anas AlMajali, Salah Ghalyon, Waleed Dweik, and 
Bassam J. Mohd as a companion to their paper:
Analyzing Cyber-physical Threats on Robotic Platforms, which is currently under review.

This work has been done at the computer engineering departmnet at the Hashemite University, Zarqa, jordan.

If you use this code in project that results in a publication, please cite the paper above. 

This README covers the type of attacks or threats that can be perofrmed using this tool on Adept robotic platforms.

May 3, 2018

Comments/Bugs/Problems: khalil@hu.edu.jo, almajali@hu.edu.jo and salah.g.ghalyon@hu.edu.jo 

Required library:

Scapy

Made Assumption(s): 

An attacker has successfully succeeded in performing man-in-the-middle (MITM) attack,
say using ARP (Address Resolution Protocol) spoofing, on the robot network. Thus, this tool will
run on the MITM attacker machine to perform the attacks presented in the paper and listed below.

To use the RAT tool, an attacker should be able to successfully perform a MITM attack. 
After which, the RAT tool sniffs the packets streamed over the network. Based on the 
direction of the traffic (robot to client and client to robot ), the RAT tool accepts five states
that indicate the type of the attack, which are assigned to a variable named as \textbf{State}. 
The first fours states represent integrity attacks, and the last one represents an availability attack.
These states are described as follows: 

	States of integrity attacks
		mirror: reverse the direction of the movement of the robot;  change right command to left, and left command to right. 
		send_to_position: replace any command by a command that forces the robot to go to a certain position of the attacker's choice. 
		circulate: replace any command by a command that forces the robot to circulate in one direction (left). 
		fake_position: change the correct position sent by the robot to the client. 
	State of an availability attack:
		availability_attack: drop the packets in any direction between the client and the robot rendering the robot unavailable.
