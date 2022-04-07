# frozen_string_literal: true

#
# Copyright:: 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

title '1.8 Ensure patches'


login_banner_text = input('login_banner_text', default: '')


control 'cis-dil-benchmark-1.8' do
  title 'Ensure updates, patches, and additional security software are installed'
  desc  "Periodically patches are released for included software either due to security flaws or to include additional functionality.\n\nRationale: Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.8'
  tag level: 1

  describe 'cis-dil-benchmark-1.8' do
    skip 'Not implemented'
  end
end

control 'cis-ubuntu-2004-benchmark-1.8.1' do
  title 'Ensure GNOME Display Manager is removed'
  desc  "The GNOME Display Manager (GDM) is a program that manages graphical display servers and handles graphical user logins.\n\nRationale: If a Graphical User Interface (GUI) is not required, it should be removed to reduce the attack surface of the system."
  impact 1.0

  tag cis: 'ubuntu-2004-linux:1.8.1'
  tag level: 2

  only_if do
    only_if { cis_level == 2 and linux_family == 'ubuntu' }
  end

  describe package('gdm3') do
    it { should_not be_installed }
  end
end

control 'cis-ubuntu-2004-benchmark-1.8.2' do
  title 'Ensure GDM login banner is configured'
  desc  "GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place."
  impact 1.0

  tag cis: 'ubuntu-2004-linux:1.8.2'
  tag level: 1

  only_if do
    package('gdm3').installed?
  end

  describe file('/etc/gdm3/greeter.dconf-defaults') do
    it { should exist }
    its(:content) { should match(/^banner-message-enable=true$/) }
    its(:content) { should match(/^banner-message-text='#{login_banner_text}'$/) }
  end
end

control 'cis-ubuntu-2004-benchmark-1.8.3' do
  title 'Ensure disable-user-list is enabled'
  desc  "GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.\n\nThe disable-user-list option controls is a list of users is displayed on the login screen\n\nRationale: Displaying the user list eliminates half of the Userid/Password equation that an unauthorized person would need to log on."
  impact 1.0

  tag cis: 'ubuntu-2004-linux:1.8.3'
  tag level: 1

  only_if do
    package('gdm3').installed?
  end

  describe file('/etc/gdm3/greeter.dconf-defaults') do
    its(:content) { should match(/^disable-user-list=true$/) }
  end
end

control 'cis-ubuntu-2004-benchmark-1.8.4' do
  title 'Ensure disable-user-list is enabled'
  desc  "X Display Manager Control Protocol (XDMCP) is designed to provide authenticated access to display management services for remote displays\n\nRationale:XDMCP is inherently insecure.\n* XDMCP is not a ciphered protocol. This may allow an attacker to capture keystrokes entered by a user\n* XDMCP is vulnerable to man-in-the-middle attacks. This may allow an attacker to steal the credentials of legitimate users by impersonating the XDMCP server."
  impact 1.0

  tag cis: 'ubuntu-2004-linux:1.8.4'
  tag level: 1

  only_if do
    package('gdm3').installed?
  end

  describe file('/etc/gdm3/custom.conf') do
    its(:content) { should_not match(/^\s*Enable\s*=\s*true/) }
  end
end
