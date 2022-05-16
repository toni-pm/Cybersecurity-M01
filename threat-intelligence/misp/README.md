---
title: "Threat Intelligence - MISP"
author: "Toni Peraira"
date: "2022-05-13"
version: "1.0"
geometry: left=2.54cm,right=2.54cm,top=2.54cm,bottom=2.54cm
header-right: '\headerlogo'
header-includes:
- '`\newcommand{\headerlogo}{\raisebox{0pt}[0pt]{\includegraphics[width=3cm]{../../institut_montilivi.png}}}`{=latex}'
---

<!--
pandoc README.md -o Toni_Peraira_Threat_Intelligence_MISP.pdf --from markdown --template eisvogel --listings --pdf-engine=xelatex
-->

Threat Intelligence - MISP
==========================


MISP Threat Sharing (Malware Information Sharing Platform)
https://www.misp-project.org/

The MISP is an open source software solution for collecting, storing, distributing and sharing cyber
security indicators and threats about cyber security. The project is funded by the European Union and the Computer Incident Response Center Luxembourg (CIRCL).

You can download a virtual machine from: https://vm.misp-project.org/latest/
It comes with the following credentials:

```
For the MISP web interface -> admin@admin.test:admin
For the system -> misp:Password1234
```

**This virtual machine is not made for production, it's not secure.**

![""](images/image01.png "")

---

**Set an administrator password for the whole system.**

Password Policy:

    [12]: Ensure that the password is at least 12 characters long

    [A-Z]: contains at least one upper-case

    [0-9| ]: includes a digit or a special character

    [a-z]: at least one lower-case character

![""](images/image02.png "")

---

# Define your organization

From the menu bar, select Add Organizations and fill the fields of your own organization.

For this example I created one for our school:

![""](images/image03.png "")

---

# Create a user with *Org admin* permissions on your new organization.

Select *Add User* from the *Administration* menu bar.

![""](images/image04.png "")

![""](images/image05.png "")

---

# Key concepts

Event: This is a study case.

Attributes: These are the information elements that shape the event.

Feeds: These are data sources that enrich our events.

Tags: Categories that we put on an event in order to classify it.

Galaxies: These are templates for describing attributes.

Cluster: Is an instance of a galaxy.


# Event

Let's understand what an event is while creating one. Suppose that a user in our organization receives an email with a suspicious link, for example: <span style="color: red;">linksys.secureshellz.net</span>
Obviously, we don't want to open the link without knowing if this domain is malware free.

From the menu bar, select *Event Actions* and *Add Event*.

Fill it with the information requested:

![""](images/image06.png "")

Now, if you list the events you should see something like this:

![""](images/image07.png "")

Let's add attributes to this event.

# Attributes

Attributes give shape and meaning to the event.

In our example, a very clear attribute is the domain that we consider suspicious.

Click on the event ID to see its contents:

![""](images/image08.png "")

Then add a new attribute from the menu. Fill the data.

![""](images/image09.png "")

# Feeds

In order to find out if someone else has found this link and has already studied it, we will add the feeds, which are serie of OSINT events that we can import.

Select the *List Feeds* option.

By default, the application has two but the are disabled.

Select and enable them.

![""](images/image10.png "")

In a short time we will start receiving events created by the two enabled feeds.
We can see events listed:

![""](images/image11.png "")

# Automatic enrichment

Now, the part that interests us is in our event. Click the event to display its content and go to its attribute.

We can see in the *Related Events* column our related event. Click it.

![""](images/image12.png "")

This event is created by the  CthulhuSPRL.be organization with data from 2014 and contains 1067 attributes.

![""](images/image13.png "")

Below the description we can see the list of all its attributes, one of which we are interested in:

![""](images/image14.png "")

So, yes, this link is already classified as ***OSINT ShellShock scanning IPs from OpenDNS***.


# Tags

Tags are used to classify and add information to an event. This is the link where MISP has collected all tags and taxonomies:

[https://www.misp-project.org/taxonomies.html](https://www.misp-project.org/taxonomies.html)

From this list we will work with one type: the TLP taconomy.

TLP (Traggic Light Protocol) is designed to classify event information depending on the data protection and reputation of the company.

They have defined the following tags:

- Red
- Amber
- Green
- White


## Activity 1

**According to the information given the taxonomies by MISP, explain briefly what involves each color in an event.**

## Activity 2

**When the event is captured in the previous page, there is a warning in the *Tags* section.**

**What is the warning telling us?**

![""](images/image15.png "")

![""](images/image16.png "")

# Galaxies

Galaxies are templates for describing more information about an event or attribute. To list them we go to *List Galaxies* from the *Galaxies* menu bar.

![""](images/image17.png "")

Let's look at one: *Threat Actor*

![""](images/image18.png "")

This is a fairly simple case, we got only a name and a description.
We can see all the published instances of this galaxy:

![""](images/image19.png "")

We select one to see its history:

![""](images/image20.png "")


# Cluster

Clusters are simply an instance of a galaxy.

## Activity 3

**Create a cluster as an instance of the *Threat Actor* galaxy, defining the attacker "Estudiant del curs de ciberseguretat Montilivi".**

**Attach a screenshot of your new cluster.**

![""](images/image21.png "")

![""](images/image22.png "")

---

In order to use this new custer, we must publish it.


Publish is not a immediate action, it may take a few minutes.

Now, we add this cluster to the created event. List events, select yours and edit it. Add a cluster MISP, *Threat Actor*, and then start typing the name of your cluster until you see it.

---

## Activity 4

**Attach a screenshot of your event from Montilivi's cluster that you just created.**

![""](images/image23.png "")

Publish the event.

![""](images/image24.png "")

![""](images/image25.png "")