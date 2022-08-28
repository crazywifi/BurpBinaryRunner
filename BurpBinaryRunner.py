#Created By lazyhacker22.blogspot.com
#Burp Binary Runner

try:
    from burp import IBurpExtender
    from burp import ITab
    from burp import IScanIssue
    from burp import IContextMenuFactory
    from burp import IExtensionStateListener
    from javax.swing import ( JScrollPane, JButton, JPanel, JTextField,
                              JLabel, SwingConstants, Box, JOptionPane,
                              JMenuItem, BoxLayout, JFileChooser, JTextPane, 
                              JTabbedPane )
    from javax.swing.border import EmptyBorder
    from java.awt import (Frame, Component, BorderLayout, FlowLayout, Dimension, Color)
    from java.net import URL
    from java.util import ArrayList
    from java.io import PrintWriter, File, FileWriter
    from java.lang import Runnable
    from urlparse import urlparse 
    from threading import Thread
    import subprocess
    import sys
    #import shlex
    #import os
    #import json


except ImportError as e:
    print e

operatingsystem = (hasattr(sys, 'getwindowsversion'))

class BurpExtender(IBurpExtender, ITab, IScanIssue, IExtensionStateListener):


    def __init__(self):
        self.cfgcmdpath = ''
        self.cfgcmdpath1 = ''
        self.cfgcmdpath2 = ''
        
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp Binary Runner")
        callbacks.addSuiteTab(self)
        self.runningSubprocesses = set()
        print("Burp Binary Runner: Extension loaded")
        print("Follow Me: https://lazyhacker22.blogspot.com/")

        self.scannerThread = None

    def getTabCaption(self):
        return "BinaryRunner"


    def getUiComponent(self):
        if self._callbacks.loadExtensionSetting("cmdpath"):
            self.cfgcmdpath = str(self._callbacks.loadExtensionSetting("cmdpath"))
        if self._callbacks.loadExtensionSetting("cmdpath1"):
            self.cfgcmdpath1 = str(self._callbacks.loadExtensionSetting("cmdpath1"))
        if self._callbacks.loadExtensionSetting("cmdpath2"):
            self.cfgcmdpath2 = str(self._callbacks.loadExtensionSetting("cmdpath2"))
        
        #mainpanel
        self.mainpanel = JPanel(BorderLayout(50,50))
        self.mainpanel.setBorder(EmptyBorder(20, 20, 20, 20))

        #1ndpanel
        self.initialText = ('<h2 style="color: red;">https://lazyhacker22.blogspot.com/</h2>')
        self.currentText = self.initialText

        self.scanResultsTextPane = JTextPane()
        self.scanResultsTextPane.setEditable(False)
        self.scanResultsTextPane.setContentType("text/html")        
        self.scanResultsTextPane.setText(self.currentText)
        self.scanResultsTab = JPanel(BorderLayout())
        self.scanResultsTab.add(JScrollPane(self.scanResultsTextPane), BorderLayout.CENTER)
        self.Settingpanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.binarypathlabel = JLabel("Binary Path:", SwingConstants.LEFT)
        self.BinaryInputBox = JTextField('' + self.cfgcmdpath,30)
        #self.BinaryInputBox.setText("Enter Binary File Path")
        self.BinaryInputBox.setForeground(Color.BLACK)
        self.BrowseButton = JButton("Browse", actionPerformed=self.Browse)
        self.extracmdlabel = JLabel("Extra Command:", SwingConstants.LEFT)
        self.CutomInputBox = JTextField(30)
        #self.CutomInputBox.setText("Enter Custom Command")
        self.CutomInputBox.setForeground(Color.BLACK)
        self.SaveButton = JButton("Run", actionPerformed=self.StartRun)
        self.TerProcess = JButton("Terminate Process", actionPerformed=self.TerminateProcess)
        self.TerProcess.setForeground(Color.RED)
        self.Settingpanel.add(self.binarypathlabel)
        self.Settingpanel.add(self.BinaryInputBox)
        self.Settingpanel.add(self.BrowseButton)
        self.Settingpanel.add(self.extracmdlabel)
        self.Settingpanel.add(self.CutomInputBox)         
        self.Settingpanel.add(self.SaveButton)
        self.Settingpanel.add(self.TerProcess)
        self.savePanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.saveButton = JButton('Save to file', actionPerformed=self.saveToFile)
        #self.saveButton.setEnabled(False)
        self.clearbutton = JButton('Clear Results', actionPerformed=self.Clear)
        self.savePanel.add(self.saveButton)
        self.savePanel.add(self.clearbutton)        


        self.scanResultsTab.add(self.Settingpanel, BorderLayout.PAGE_START)
        self.scanResultsTab.add(self.savePanel, BorderLayout.PAGE_END)        
        

        #2ndpanel
        self.initialText1 = ('<h2 style="color: red;">https://lazyhacker22.blogspot.com/</h2>')
        self.currentText1 = self.initialText1
        self.scanResultsTextPane1 = JTextPane()
        self.scanResultsTextPane1.setEditable(False)
        self.scanResultsTextPane1.setContentType("text/html")
        self.scanResultsTextPane1.setText(self.currentText1)
        self.scanResultsTab1 = JPanel(BorderLayout())
        self.scanResultsTab1.add(JScrollPane(self.scanResultsTextPane1), BorderLayout.CENTER)        
        self.Settingpanel1 = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.binarypathlabel1 = JLabel("Binary Path:", SwingConstants.LEFT)
        self.BinaryInputBox1 = JTextField('' + self.cfgcmdpath1,30)
        #self.BinaryInputBox1.setText("Enter Binary File Path")
        self.BinaryInputBox1.setForeground(Color.BLACK)
        self.BrowseButton1 = JButton("Browse", actionPerformed=self.Browse1)
        self.extracmdlabel1 = JLabel("Extra Command:", SwingConstants.LEFT)
        self.CutomInputBox1 = JTextField(30)
        #self.CutomInputBox1.setText("Enter Custom Command")
        self.CutomInputBox1.setForeground(Color.BLACK)
        self.SaveButton1 = JButton("Run", actionPerformed=self.StartRun1)
        self.TerProcess1 = JButton("Terminate Process", actionPerformed=self.TerminateProcess1)
        self.TerProcess1.setForeground(Color.RED)
        self.Settingpanel1.add(self.binarypathlabel1)
        self.Settingpanel1.add(self.BinaryInputBox1)
        self.Settingpanel1.add(self.BrowseButton1)
        self.Settingpanel1.add(self.extracmdlabel1)
        self.Settingpanel1.add(self.CutomInputBox1)        
        self.Settingpanel1.add(self.SaveButton1)
        self.Settingpanel1.add(self.TerProcess1)
        self.savePanel1 = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.saveButton1 = JButton('Save to file', actionPerformed=self.saveToFile1)
        #self.saveButton1.setEnabled(False)
        self.clearbutton1 = JButton('Clear Results', actionPerformed=self.Clear1)
        self.savePanel1.add(self.saveButton1)
        self.savePanel1.add(self.clearbutton1)   


        self.scanResultsTab1.add(self.Settingpanel1, BorderLayout.PAGE_START)
        self.scanResultsTab1.add(self.savePanel1, BorderLayout.PAGE_END)



        #3rdpanel
        self.initialText2 = ('<h2 style="color: red;">https://lazyhacker22.blogspot.com/</h2>')
        self.currentText2 = self.initialText2
        self.scanResultsTextPane2 = JTextPane()
        self.scanResultsTextPane2.setEditable(False)
        self.scanResultsTextPane2.setContentType("text/html")
        self.scanResultsTextPane2.setText(self.currentText2)
        self.scanResultsTab2 = JPanel(BorderLayout())
        self.scanResultsTab2.add(JScrollPane(self.scanResultsTextPane2), BorderLayout.CENTER)        
        self.Settingpanel2 = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.binarypathlabel2 = JLabel("Binary Path:", SwingConstants.LEFT)
        self.BinaryInputBox2 = JTextField('' + self.cfgcmdpath2,30)
        #self.BinaryInputBox2.setText("Enter Binary File Path")
        self.BinaryInputBox2.setForeground(Color.BLACK)
        self.BrowseButton2 = JButton("Browse", actionPerformed=self.Browse2)
        self.extracmdlabel2 = JLabel("Extra Command:", SwingConstants.LEFT)
        self.CutomInputBox2 = JTextField(30)
        #self.CutomInputBox2.setText("Enter Custom Command")
        self.CutomInputBox2.setForeground(Color.BLACK)
        self.SaveButton2 = JButton("Run", actionPerformed=self.StartRun2)
        self.TerProcess2 = JButton("Terminate Process", actionPerformed=self.TerminateProcess2)
        self.TerProcess2.setForeground(Color.RED)
        self.Settingpanel2.add(self.binarypathlabel2)
        self.Settingpanel2.add(self.BinaryInputBox2)
        self.Settingpanel2.add(self.BrowseButton2)
        self.Settingpanel2.add(self.extracmdlabel2)
        self.Settingpanel2.add(self.CutomInputBox2)        
        self.Settingpanel2.add(self.SaveButton2)
        self.Settingpanel2.add(self.TerProcess2)
        self.savePanel2 = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.saveButton2 = JButton('Save to file', actionPerformed=self.saveToFile2)
        #self.saveButton2.setEnabled(False)
        self.clearbutton2 = JButton('Clear Results', actionPerformed=self.Clear2)
        self.savePanel2.add(self.saveButton2)
        self.savePanel2.add(self.clearbutton2)   


        self.scanResultsTab2.add(self.Settingpanel2, BorderLayout.PAGE_START)
        self.scanResultsTab2.add(self.savePanel2, BorderLayout.PAGE_END)


        #tabpane        
        self.tabPane = JTabbedPane(JTabbedPane.TOP)
        self.tabPane.addTab("CMD1",self.scanResultsTab)
        self.tabPane.addTab("CMD2",self.scanResultsTab1)
        self.tabPane.addTab("CMD3",self.scanResultsTab2)
        self.mainpanel.add(self.tabPane)

        return self.mainpanel

    #______________________________________________________________________________#
    #1stpanel 
    def Browse(self,e):
        chooseFile = JFileChooser()
        chooseFile.setFileSelectionMode(JFileChooser.FILES_ONLY)
        returnedFile = chooseFile.showDialog(self.mainpanel, "Open")
        if returnedFile == JFileChooser.APPROVE_OPTION: 
            fileLoad = chooseFile.getSelectedFile()
            self.filepath = fileLoad.getAbsolutePath()
            self.BinaryInputBox.text = self.filepath
            self.BinaryInputBox.setForeground(Color.BLACK)
            self.saveConfig()


    def StartRun(self,ev):
        FilePath = self.BinaryInputBox.getText()
        Custompath = self.CutomInputBox.getText()
        cmd = (str(FilePath)+" "+str(Custompath))
        print(cmd)
        self.scannerThread = Thread(target=self.Run, args=(cmd,))
        self.scannerThread.start()
        #self.Run(cmd)
                
        
    def Run(self,cmd0):
        #parsedCmd = shlex.split(cmd0, posix=True)
        #print(parsedCmd)
        try:
            p = subprocess.Popen(cmd0, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.TerProcess.putClientProperty("pid", p.pid)
            self.TerProcess.putClientProperty("proc", p)
            for line in iter(p.stdout.readline, b''):
                #print(str(line.decode('utf-8').strip()))
                out = str(line.decode('utf-8').strip())
                out = str(line.strip())
                self.updateText(out)
        except Exception as e:
                print(e)

    def updateText(self, stringToAppend):
        self.currentText += ('<br />' + stringToAppend)
        self.scanResultsTextPane.setText(self.currentText)


    def Clear(self,e):
        self.scanResultsTextPane.setText('<h2 style="color: red;">https://lazyhacker22.blogspot.com/</h2>')


    def saveToFile(self, e1):
        saveme = (self.scanResultsTextPane.getText())
        self.savefilechooser = JFileChooser()
        self.savefilechooser.setDialogTitle("Specify a file name to save")
        self.savefilechooser.setSelectedFile(File("CMD1.html"))
        userSelection = self.savefilechooser.showSaveDialog(self.mainpanel)
        if userSelection == JFileChooser.APPROVE_OPTION:
            filetosave = self.savefilechooser.getSelectedFile()
            fw = FileWriter(filetosave)
            fw.write(saveme)
            fw.close()

        #print(saveme)
        

    def TerminateProcess(self,button):
        proc = button.getSource().getClientProperty("proc")
        pid = button.getSource().getClientProperty("pid")
        #print(proc)
        #print(pid)
        print("Process Terminated: "+str(pid))
        self.updateText('<h4 style="color: red;">Process Terminated</h4>')
        proc.terminate()
        
    def saveConfig(self):
        self._callbacks.saveExtensionSetting("cmdpath",str(self.BinaryInputBox.getText()))
        self._callbacks.saveExtensionSetting("cmdpath1",str(self.BinaryInputBox1.getText()))
        self._callbacks.saveExtensionSetting("cmdpath2",str(self.BinaryInputBox2.getText()))
        


    #______________________________________________________________________________#
    #2ndpanel    
    def Browse1(self,e):
        chooseFile = JFileChooser()
        chooseFile.setFileSelectionMode(JFileChooser.FILES_ONLY)
        returnedFile = chooseFile.showDialog(self.mainpanel, "Open")
        if returnedFile == JFileChooser.APPROVE_OPTION: 
            fileLoad = chooseFile.getSelectedFile()
            self.filepath = fileLoad.getAbsolutePath()
            self.BinaryInputBox1.text = self.filepath
            self.BinaryInputBox1.setForeground(Color.BLACK)
            self.saveConfig()



    def StartRun1(self,ev):
        FilePath1 = self.BinaryInputBox1.getText()
        Custompath1 = self.CutomInputBox1.getText()
        cmd1 = (str(FilePath1)+" "+str(Custompath1))
        print(cmd1)
        self.scannerThread = Thread(target=self.Run1, args=(cmd1,))
        self.scannerThread.start()
        #self.Run(cmd)
                
        
    def Run1(self,cmd1):
        #print("test2")
        #parsedCmd1 = shlex.split(cmd2, posix=True)
        #print(parsedCmd)
        try:
            p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.TerProcess1.putClientProperty("pid1", p1.pid)
            self.TerProcess1.putClientProperty("proc1", p1)            
            for line1 in iter(p1.stdout.readline, b''):
                #print(str(line1.decode('utf-8').strip()))
                out1 = str(line1.decode('utf-8').strip())
                self.updateText1(out1)
        except Exception as e:
                print(e)

    def updateText1(self, stringToAppend):
        self.currentText1 += ('<br />' + stringToAppend)
        self.scanResultsTextPane1.setText(self.currentText1)


    def Clear1(self,e):
        self.scanResultsTextPane1.setText('<h2 style="color: red;">https://lazyhacker22.blogspot.com/</h2>')



    def saveToFile1(self, e2):
        saveme1 = (self.scanResultsTextPane1.getText())
        self.savefilechooser1 = JFileChooser()
        self.savefilechooser1.setDialogTitle("Specify a file name to save")
        self.savefilechooser1.setSelectedFile(File("CMD2.html"))
        userSelection1 = self.savefilechooser1.showSaveDialog(self.mainpanel)
        if userSelection1 == JFileChooser.APPROVE_OPTION:
            filetosave1 = self.savefilechooser1.getSelectedFile()
            fw1 = FileWriter(filetosave1)
            fw1.write(saveme1)
            fw1.close()

        #print(saveme1)

    def TerminateProcess1(self,button):
        proc1 = button.getSource().getClientProperty("proc1")
        pid1 = button.getSource().getClientProperty("pid1")
        #print(proc1)
        #print(pid1)
        print("Process Terminated: "+str(pid1))
        self.updateText1('<h4 style="color: red;">Process Terminated</h4>')
        proc1.terminate()

    #______________________________________________________________________________#
    #3rdpanel


    def Browse2(self,e):
        chooseFile = JFileChooser()
        chooseFile.setFileSelectionMode(JFileChooser.FILES_ONLY)
        returnedFile = chooseFile.showDialog(self.mainpanel, "Open")
        if returnedFile == JFileChooser.APPROVE_OPTION: 
            fileLoad = chooseFile.getSelectedFile()
            self.filepath = fileLoad.getAbsolutePath()
            self.BinaryInputBox2.text = self.filepath
            self.BinaryInputBox2.setForeground(Color.BLACK)
            self.saveConfig()



    def StartRun2(self,ev):
        FilePath2 = self.BinaryInputBox2.getText()
        Custompath2 = self.CutomInputBox2.getText()
        cmd2 = (str(FilePath2)+" "+str(Custompath2))
        print(cmd2)
        self.scannerThread = Thread(target=self.Run2, args=(cmd2,))
        self.scannerThread.start()
        #self.Run(cmd)
                
        
    def Run2(self,cmd2):
        #print("test2")
        #parsedCmd2 = shlex.split(cmd2, posix=True)
        #print(parsedCmd)
        try:
            p2 = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.TerProcess2.putClientProperty("pid2", p2.pid)
            self.TerProcess2.putClientProperty("proc2", p2)            
            for line2 in iter(p2.stdout.readline, b''):
                #print(str(line2.decode('utf-8').strip()))
                out2 = str(line2.decode('utf-8').strip())
                self.updateText2(out2)
        except Exception as e:
                print(e)

    def updateText2(self, stringToAppend):
        self.currentText2 += ('<br />' + stringToAppend)
        self.scanResultsTextPane2.setText(self.currentText2)


    def Clear2(self,e):
        self.scanResultsTextPane2.setText('<h2 style="color: red;">https://lazyhacker22.blogspot.com/</h2>')



    def saveToFile2(self, e2):
        saveme2 = (self.scanResultsTextPane2.getText())
        self.savefilechooser2 = JFileChooser()
        self.savefilechooser2.setDialogTitle("Specify a file name to save")
        self.savefilechooser2.setSelectedFile(File("CMD3.html"))
        userSelection2 = self.savefilechooser2.showSaveDialog(self.mainpanel)
        if userSelection2 == JFileChooser.APPROVE_OPTION:
            filetosave2 = self.savefilechooser2.getSelectedFile()
            fw2 = FileWriter(filetosave2)
            fw2.write(saveme2)
            fw2.close()

        #print(saveme2)

    def TerminateProcess2(self,button):
        proc2 = button.getSource().getClientProperty("proc2")
        pid2 = button.getSource().getClientProperty("pid2")
        #print(proc2)
        #print(pid2)
        print("Process Terminated: "+str(pid2))
        self.updateText2('<h4 style="color: red;">Process Terminated</h4>')
        proc2.terminate()
