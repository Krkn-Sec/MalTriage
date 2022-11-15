import sys
import os
import magic
import subprocess
import pprint
from datetime import date

def getHashes(file, folderPath):
    os.system("ssdeep " + file + " > " + folderPath + "/SampleHashes.txt")
    os.system("md5sum " + file + " >> " + folderPath + "/SampleHashes.txt")
    os.system("sha1sum " + file + " >> " + folderPath + "/SampleHashes.txt")
    os.system("sha256sum " + file + " >> " + folderPath + "/SampleHashes.txt")
    print("[+] Grabbed file hashes. Hashes saved: " + folderPath + "/SampleHashes.txt")

def getDiE(file, folderPath):
    # Get Basic
    os.system("diec -i " + file + " > " + folderPath + "/DiE_Report.txt")

    # Get compiler/packer
    os.system("diec -r " + file + " >> " + folderPath + "/DiE_Report.txt")

    # Get Entropy
    os.system("diec -e " + file + " >> " + folderPath + "/DiE_Report.txt")
    print("[+] Grabbed Detect-It-Easy results. Report saved: " + folderPath + "/DiE_Report.txt")

def winPath(file):
    # Get date and append to folder path to make a new directory
    print("[!] Creating report directory...")
    
    try:
        today = date.today()
        folderPath = str(today) + "-Triage-Reports"
        os.system("mkdir " + folderPath)
        print("[+] Created report directory!")
    except:
        print("[-] Could not create report directory!")

    # Get strings and rank them for strings report
    print("[!] Attempting to grab and rank strings from binary...")
    try:
        os.system("flarestrings " + file + " | rank_strings > " + folderPath + "/stringsReport.txt")
        print("[+] Grabbed strings and ranked by score! Report saved: " +folderPath+"/stringsReport.txt")
    except:
        print("[-] Could not grab and rank strings!")

    # Get TrID results
    print("[!] Attempting to grab TrID results...")
    try:
        os.system("trid " + file + " > " + folderPath + "/TrID_Report.txt")
        print("[+] TrID results saved: " + folderPath + "/TrID_Report.txt")
    except:
        print("[-] Could not get TrID results!")

    # Get DiE results
    print("[!] Attempting to get Detect-It-Easy results...")
    try:
        getDiE(file, folderPath)
    except:
        print("[-] Could not get Detect-It-Easy results!")

    # Get signsrch results
    print("[!] Attempting to get SignSrch results...")
    try:
        cmd = "signsrch " + file + " > " + folderPath + "/SignSrch_Report.txt"
        sp = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        rc = sp.wait()
        print("[+] SignSrch results saved: " + folderPath + "/SignSrch_Report.txt")
    except:
        print("[-] Could not get SignSrch results!")
    #os.system("signsrch " + file + " > " + folderPath + "/SignSrch_Report.txt")

    # Get sample hashes
    print("[!] Attempting to get Detect-It-Easy results...")
    try:
        getHashes(file, folderPath)
    except:
        print("[-] Could not get file hashes!")

    # Get Balbuzard results
    print("[!] Attempting to get Balbuzard results...")
    try:
        os.system("balbuzard " + file + " > " + folderPath + "/Balbuzard_Report.txt")
        print("[+] Balbuzard results saved: " + folderPath + "/Balbuzard_Report.txt")
    except:
        print("[-] Could not get Balbuzard report!")

    # Get any XOR strings
    print("[!] Attempting to find and decode XOR'd strings...")
    try:
        os.system("brxor.py " + file + " > " + folderPath + "/Possible_XOR_Strings.txt")
        print("[+] XOR string results saved: " + folderPath + "/Possible_XOR_Strings.txt")
    except:
        print("[-] Could not find and decode XOR'd strings!")

    # Get stack strings
    print("[!] Attempting to find and print stack strings...")
    try:
        os.system("strdeob.pl " + file + " > " + folderPath + "/Possible_Stack_Strings.txt")
        print("[+] Stack strings results saved: " + folderPath + "/Possible_Stack_Strings.txt")
    except:
        print("[-] Could not find and print stack strings!")

    # Get FLOSS results
    print("[!] Attempting to run FLOSS...")
    try:
        cmd = "floss " + file + " > " + folderPath + "/FLOSS_Strings.txt"
        sp = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        rc = sp.wait()
        print("[+] FLOSS results saved: " + folderPath + "/FLOSS_Strings.txt")
    except:
        print("[-] Could not run FLOSS!")
    #os.system("floss " + file + " > " + folderPath + "/FLOSS_Strings.txt")

    # Get CAPA results
    print("[!] Attempting to run CAPA...")
    try:
        cmd1 = "capa " + file + " > " + folderPath + "/CAPA_Report.txt"
        cmd2 = "capa -vv " + file + " >> " + folderPath + "/CAPA_Report.txt"
        sp1 = subprocess.Popen(cmd1,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        rc1 = sp1.wait()
        sp2 = subprocess.Popen(cmd2,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        rc2 = sp2.wait()
        print("[+] CAPA results saved: " + folderPath + "/CAPA_Report.txt")
    except:
        print("[-] Could not run CAPA!")

    # Place proper permissions on reports folder
    user = os.getenv("SUDO_USER")
    os.system("chown -R " +user+":"+user+ " " + folderPath)

    os.system("clear")
    banner()
    print("[+] All done!")

def banner():
    print("""
ooo        ooooo           oooo  ooooooooooooo           o8o                                 
`88.       .888'           `888  8'   888   `8           `"'                                 
 888b     d'888   .oooo.    888       888      oooo d8b oooo   .oooo.    .oooooooo  .ooooo.  
 8 Y88. .P  888  `P  )88b   888       888      `888""8P `888  `P  )88b  888' `88b  d88' `88b 
 8  `888'   888   .oP"888   888       888       888      888   .oP"888  888   888  888ooo888 
 8    Y     888  d8(  888   888       888       888      888  d8(  888  `88bod8P'  888    .o 
o8o        o888o `Y888""8o o888o     o888o     d888b    o888o `Y888""8o `8oooooo.  `Y8bod8P' 
                                                                        d"     YD            
                                                                        "Y88888P'            
==============================================================================================

Description: Statically triage new samples all under one roof. Uses a variety
             of different scripts/tools within REMnux and generates reports automatically.

Author: KrknSec

==============================================================================================
""")

def getFileType(file):
    return magic.from_file(file, mime=True)

def main():
    # Check if script was ran with root for CAPA
    userEnv = os.getenv("USER")

    if (userEnv != "root"):
        print("[!] Please run with sudo!")
        exit()

    # Get file from user
    args = input("[!] Please specify the path to the file you'd like to triage: ")

    # Get the file type and proceed down the proper path
    fileType = getFileType(args)
    if (fileType == "application/x-dosexec"):
        winPath(args)
    else:
        print("[-] Unsupported file type!")
    
banner()
main()
