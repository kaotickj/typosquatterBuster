#!/usr/bin/env python3
"""
Title: Typosquatter Buster
Author: Kaotick Jay (https://github.com/kaotickj)
Description: This script detects typosquatting domains by generating typo variations of a given domain name, checking if they return a valid HTTP response, and running a WHOIS lookup to determine if the domain is registered. It generates an HTML report with the findings.
Instructions: Run the script, enter a domain name, and click "Run Detection" to check for typosquatting domains. The script will display the variations being checked and generate an HTML report upon completion.
"""

import os
import re
import requests
import whois
import tkinter as tk
from tkinter import messagebox
from datetime import datetime


# Regular expression to generate typo variations
def generate_typos(domain):
    variations = set()
    parts = domain.split('.')
    if len(parts) != 2:
        return []

    domain_name, tld = parts

    for i in range(len(domain_name)):
        # Missing character
        variations.add(domain_name[:i] + domain_name[i + 1:] + '.' + tld)
        # Additional character
        for c in 'abcdefghijklmnopqrstuvwxyz0123456789':
            variations.add(domain_name[:i] + c + domain_name[i:] + '.' + tld)
        # Character swap
        if i < len(domain_name) - 1:
            variations.add(domain_name[:i] + domain_name[i + 1] + domain_name[i] + domain_name[i + 2:] + '.' + tld)

    return variations


# Check if a domain variation returns a valid HTTP response
def check_http_response(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        return response.status_code == 200
    except:
        return False


# Function to run the typosquatting detection
def run_detection():
    domain = entry.get()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain.")
        return

    # Clear previous output
    output_text.delete("1.0", tk.END)

    typosquatters = []
    non_typosquatters = []
    whois_data = {}

    # Generate typos for the user-supplied domain and check if it's a typosquatter
    variations = generate_typos(domain)
    for variation in variations:
        print(f"Checking variation: {variation}")
        output_text.delete("1.0", tk.END)  # Clear previous output before updating
        output_text.insert(tk.END, f"Checking variation: {variation}\n")
        output_text.update_idletasks()  # Update the text widget to show the current domain being checked
        if check_http_response(variation):
            try:
                w = whois.whois(variation)
                if w.domain_name not in typosquatters:
                    typosquatters.append(w.domain_name)
                    whois_data[w.domain_name] = w.text
            except Exception as e:
                error_msg = f"Error getting whois for domain {variation}: {e}"
                print(error_msg)
                output_text.insert(tk.END, f"{error_msg}\n")
        else:
            non_typosquatters.append(variation)
        output_text.insert(tk.END, f"\nDone!")

    # Print some summary information
    print(f"Total variations checked: {len(variations)}")
    print(f"Total typosquatters found: {len(typosquatters)}")
    print(f"Total non-typosquatters found: {len(non_typosquatters)}")

    # Create directory for reports if it does not exist
    reports_dir = "typosquatter_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    # Write HTML report
    report_filename = f"{domain}_report.html"
    with open(os.path.join(reports_dir, report_filename), "w") as report_file:
        report_file.write(f"<!doctype html><html lang='en'><head><title>TypoSquatter Report for {domain}</title>")
        report_file.write('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        report_file.write(
            '<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" type="text/css">')
        report_file.write(
            '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" type="text/css">')
        report_file.write("<style>ul li{list-style-type:none;}</style></head><body>")
        report_file.write(f"<div class='container mt-4'>")
        report_file.write(
            f"<img src='https://kdgwebsolutions.com/TypoSquatter-Buster.png'><br><div><table style='margin:0px auto;text-align:center;'><th><a href='https://tryhackme.com/p/kaotickj'target='_blank' title='Kaotick Jay on Try Hack Me'>Try Hack Me</a></th><th><a href='https://app.hackthebox.com/profile/476578'target='_blank' title='Kaotick Jay on Hack the Box'>Hack the Box</a></th><tr><td><script src='https://tryhackme.com/badge/1863463'></script></td><td><img src='https://www.hackthebox.eu/badge/image/476578' alt='Kaotick Jay on Hack The Box'></td></tr></table></div><br>")
        report_file.write("<h2>What is \"Typo Squatting\"</h2>")
        report_file.write(
            "<p>Typosquatting, also known as URL hijacking, is a deceptive practice where someone registers domain names that closely resemble legitimate, well-known websites. These fake domains are designed to exploit common typing errors or misspellings that users might make when entering a web address.</p>")
        report_file.write(
            "<p>The goal of typosquatters is often to capitalize on user mistakes by directing them to their websites instead of the intended ones. Once on these fake sites, users may encounter malicious content, such as phishing scams, malware downloads, or counterfeit goods.</p>")
        report_file.write(
            "<p>For example, a typosquatter might register a domain like \"gooogle.com\" (with an extra 'o') to target users who accidentally add a letter when typing \"google.com.\" The typosquatter's site could mimic the look and feel of the real Google site, potentially tricking users into entering sensitive information or downloading harmful software.</p>")
        report_file.write(f"<h1 class='mb-4'>TypoSquatter Report for \"{domain}\"</h1>")
        report_file.write(
            f"<p><em>This report was generated by TypoSquatter Buster by <a href='https://github.com/kaotickj' target='_blank'>Kaotick Jay</a></em></p>")
        report_file.write(f"<p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        report_file.write(f"<p>Total number of domains checked: {len(variations)}</p>")
        report_file.write(f"<p>Total number of typosquatters found: {len(typosquatters)}</p>")
        report_file.write("<div class='mt-4'>")
        report_file.write(
            f"<h2>List of Registered Typosquatter Domains Similar to \"{domain}\":<small>(skip to <a href='#notsquat'>Unregistered TypoSquatter Domains</a>)</small></h2><blockquote><p>*** Note: List entries in square brackets (i.e., ['DOMAIN.COM', 'domain.com']) did not return valid whois data, but did return a valid http response indicating a valid domain. This is probably due to a request timeout, and you should run TypoSquatter Buster against the domain again if you want to try populating the whois data again. Otherwise, you can run a manual whois query. </p></blockquote>")
        report_file.write("<ul id='top'>")
        for typosquatter in typosquatters:
            report_file.write(
                f"<li><i class='fas fa-exclamation-circle me-2' style='color: #ff0000;'></i> <a href='#{typosquatter}'>{typosquatter}</a></li>")
        report_file.write("</ul>")
        report_file.write("</div>")
        report_file.write("<div class='mt-4'>")
        report_file.write("<h2>Whois Data for Registered Typosquatters:</h2>")
        report_file.write("<ul>")
        for domain_name, data in whois_data.items():
            report_file.write(
                f"<li><b id='{domain_name}'>{domain_name}</b>:<br><pre>{data}</pre></li><p><a href='#top' class='btn btn-primary'>Back to list</a></p> ")
        report_file.write("</ul>")
        report_file.write("</div>")
        report_file.write("<div class='mt-4'>")
        report_file.write("<h2 id='notsquat'>List of Domains Checked that were not Registered</h2>")
        report_file.write(
            f"<p>These domains that closely match \"{domain}\" returned an invalid http status so are presumably not registered. This is not definitive, as an invalid http status can happen even when a domain is valid. Run a manual whois to verify.</p>")
        report_file.write("<ul>")
        for non_typosquatter in non_typosquatters:
            report_file.write(
                f"<li><i class='fas fa-check-circle me-2' style='color: #008000;'></i> {non_typosquatter}</li>")
        report_file.write("</ul><p><a href='#top' class='btn btn-primary'>Back to list</a></p><br>")
        report_file.write("</div>")
        report_file.write("</div>")
        #        report_file.write('<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.4.0/dist/js/bootstrap.bundle.min.js"></script>')
        report_file.write("</body></html>")

    messagebox.showinfo("Complete",
                        f"Typosquatting detection complete. HTML report generated.\nReport saved in: {os.path.abspath(reports_dir)}")


def show_help():
    help_text = """
    This script checks a domain for typosquatters by generating various typos of the domain name and checking if they return a valid HTTP response. If a valid response is received, it then runs a WHOIS lookup to determine if the domain is registered.

    To use the script, enter a domain name in the provided field and click the "Run Detection" button. The script will display the variations of the domain being checked and any errors encountered during the process. The script will generate and save a report in html upon completion.

    The HTML report will contain:
    - A list of registered typosquatter domains with links to their WHOIS data.
    - WHOIS data for registered typosquatter domains.
    - A list of domains checked that were not registered as typosquatters.
    """
    messagebox.showinfo("Help", help_text)


def show_about():
    about_text = "TypoSquatter Buster\n\nAuthor: KaotickJ\nGitHub: https://github.com/kaotickj"
    messagebox.showinfo("About", about_text)


# Create the GUI
root = tk.Tk()
root.title("TypoSquatter Buster")
root.geometry("600x400")
root.config(bg="lightgrey")

# Create menubar
menubar = tk.Menu(root)
help_menu = tk.Menu(menubar, tearoff=0)
help_menu.add_command(label="Help", command=show_help)
help_menu.add_command(label="About", command=show_about)
menubar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menubar)

label = tk.Label(root, text="Enter a domain to check for typosquatters:")
label.config(font=("Arial", 16), bg="lightgray", fg="navy")
label.pack(pady=10)

entry = tk.Entry(root)
entry.config(font=("Arial", 12))
entry.pack(pady=5)

button = tk.Button(root, text="Run Detection", command=run_detection)
button.config(font=("Arial", 14), bg="steelblue", fg="white")
button.pack(pady=10)

output_text = tk.Text(root)
output_text.config(font=("Courier", 12), fg="black", bg="white")
output_text.pack()

root.mainloop()
