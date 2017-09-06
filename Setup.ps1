# Windows 10 Post-Install Setup #
# 	  Written by MetaVulpes		#
#################################

#################
# Get Setup URL #
#################

# START http://boxstarter.org/package/nr/url?<INSERT GITHUB SCRIPT URL>

#####################################
# Set Execution Policy; Disable UAC #
#####################################

Set-ExecutionPolicy Unrestricted

Disable-UAC

##########################################
# Install Chocolatey; Install Boxstarter #
##########################################

iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex

choco install -y boxstarter

##################
# Disable Defrag #
##################

Get-ScheduledTask -TaskName *defrag* | Disable-ScheduledTask

##################
# Windows Update #
##################

Install-WindowsUpdate -AcceptEula -GetUpdatesFromMS
if (Test-PendingReboot) { Invoke-Reboot }

Disable-MicrosoftUpdate

####################
# Software Install #
####################

choco install -y firefox

choco install -y 7zip.install

choco install -y skype

choco install -y sysinternals

choco install -y keepass.install

choco install -y malwarebytes

choco install -y sublimetext3

choco install -y vlc

choco install -y qbittorrent

choco install -y steam

choco install -y chocolateygui

choco install -y ccleaner

choco install -y ccenhancer

choco install -y vmwareworkstation

choco install -y discord

###########################################
# Schedule Updates to Chocolatey Packages #
###########################################

schtasks.exe /create /s "localhost" /ru "System" /tn "Update Chocolatey packages" /tr "%ChocolateyInstall%\bin\cup all" /sc DAILY /st 06:00 /F
Write-BoxstarterMessage "Update Schedule for Chocolatey Packages Finished"
if (Test-PendingReboot) { Invoke-Reboot }

###########################
# Move Directories to HDD #
###########################

Move-LibraryDirectory "Documents" "D:\Documents"
Move-LibraryDirectory "Downloads" "D:\Downloads"
Move-LibraryDirectory "Music" "D:\Music"
Move-LibraryDirectory "Pictures" "D:\Pictures"
Move-LibraryDirectory "Videos" "D:\Videos"

#############################
# Associate File Extensions #
#############################

Install-ChocolateyFileAssociation ".txt" "$env:programfiles\Sublime Text 3\sublime_text.exe"

##############################################################
# Update Execution Policy; Enable Windows Update; Enable UAC #
##############################################################

Set-ExecutionPolicy Restricted

Enable-Microsoft Update

Install-WindowsUpdate -acceptEula -GetUpdatesFromMS

Enable-UAC

#################
# End of Script #
#################