package com.standard;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;


public class AppMainGUI extends JFrame implements ActionListener {
	
	private JButton clientGUI, serverGUI;
	private JComboBox securityChooser;
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 188889L;
	

	public AppMainGUI() {
		//WINDOW INIT
		setSize(200,150);
		setName("Secured Chat Server v0.3");
		setLayout(null);
		setResizable(false);
		//BUTTONS INIT
		clientGUI = new JButton ("Start Client");
		serverGUI = new JButton ("Start Server");
		clientGUI.setBounds(20, 20, 150, 20);
		serverGUI.setBounds(20, 50, 150, 20);
		add(clientGUI);
		add(serverGUI);
		clientGUI.addActionListener(this);
		serverGUI.addActionListener(this);
		
		//CHOOSER INIT
		securityChooser = new JComboBox();
		securityChooser.setBounds(20, 70, 150, 20);
		securityChooser.addItem("RSA");
		securityChooser.addItem("Diffie-Helman");
		securityChooser.addItem("Merkle Puzzel's");
		securityChooser.addItem("TTP");
		securityChooser.addItem("PreDistributed");
		add(securityChooser);
		securityChooser.addActionListener(this);
	}
	
	public static void main(String[] args) {
		//WINDOW OPEN
		AppMainGUI mainWin  = new AppMainGUI();
		mainWin.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		mainWin.setVisible(true);
		
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
		//System.out.println(new Date());
			Object o = e.getSource();
			
			if(o == clientGUI){
			String host = "localhost";
			ClientGUI client = new ClientGUI(host ,1500);
			return;
			}
			
			if(o == serverGUI){
			ServerGUI server = new ServerGUI(1500);
			return;
			}
		
		
	}

	
}
