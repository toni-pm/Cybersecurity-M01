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
pandoc README.md -o Toni_Peraira_Threat_Intelligence_MISP.pdf --from markdown --template eisvogel --listings --pdf-engine=xelatex --toc -s -V toc-title:"Index"
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

!["MISP Login"](images/image01.png "MISP Login")

---

**Set an administrator password for the whole system.**

Password Policy:

    [12]: Ensure that the password is at least 12 characters long

    [A-Z]: contains at least one upper-case

    [0-9| ]: includes a digit or a special character

    [a-z]: at least one lower-case character

!["Change password"](images/image02.png "Change password")

---

# Define your organization

From the menu bar, select Add Organizations and fill the fields of your own organization.

For this example I created one for our school:

![""](images/image03.png "")

---

# Create a user with *Org admin* permissions on your new organization.

Select *Add User* from the *Administration* menu bar.

!["Add User"](images/image04.png "Add User")

!["List Users"](images/image05.png "List Users")

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

!["Add Event"](images/image06.png "Add Event")

Now, if you list the events you should see something like this:

!["List Events"](images/image07.png "List Events")

Let's add attributes to this event.

# Attributes

Attributes give shape and meaning to the event.

In our example, a very clear attribute is the domain that we consider suspicious.

Click on the event ID to see its contents:

!["Event info"](images/image08.png "Event info")

Then add a new attribute from the menu. Fill the data.

!["Add Attribute"](images/image09.png "Add Attribute")

# Feeds

In order to find out if someone else has found this link and has already studied it, we will add the feeds, which are serie of OSINT events that we can import.

Select the *List Feeds* option.

By default, the application has two but the are disabled.

Select and enable them.

!["List Feeds"](images/image10.png "List Feeds")

In a short time we will start receiving events created by the two enabled feeds.
We can see events listed:

!["Events created"](images/image11.png "Events created")

# Automatic enrichment

Now, the part that interests us is in our event. Click the event to display its content and go to its attribute.

We can see in the *Related Events* column our related event. Click it.

!["Related Events"](images/image12.png "Related Events")

This event is created by the  CthulhuSPRL.be organization with data from 2014 and contains 1067 attributes.

!["View Event"](images/image13.png "View Event")

Below the description we can see the list of all its attributes, one of which we are interested in:

!["List Attributes"](images/image14.png "List Attributes")

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

- **Red**

For information that is limited to selected persons and its disclosure could have a negative impact on operations.

It can be distributed only to designated persons.

- **Amber**

For internal information that with its misuse or distribution would cause privacy risks affecting reputation and operations.

It can be distributed only with the members of the organization who are authorized to have knowledge of the information.

- **Green**

For all the information that can be shared in the organization and with third parties.

It can be distributed to partner organizations, but not by public means.

- **White**

For information that can be used without causing any risk in case it's misused.

Information can be shared publicly in accordance with the law.

## Activity 2

**When the event is captured in the previous page, there is a warning in the *Tags* section.**

**What is the warning telling us?**

!["Warning"](images/image15.png "Warning")

It's saying that this taxonomy is exclusive, therefore it only makes sense to have one tls color. 

If we remove one of the colors we will no longer see the warning.

!["Warning corrected"](images/image16.png "Warning corrected")

# Galaxies

Galaxies are templates for describing more information about an event or attribute. To list them we go to *List Galaxies* from the *Galaxies* menu bar.

!["List Galaxies"](images/image17.png "List Galaxies")

Let's look at one: *Threat Actor*

![""](images/image18.png "")

This is a fairly simple case, we got only a name and a description.
We can see all the published instances of this galaxy:

!["Threat Actor galaxy"](images/image19.png "Threat Actor galaxy")

We select one to see its history:

!["Instances of the galaxy"](images/image20.png "Instances of the galaxy")


# Cluster

Clusters are simply an instance of a galaxy.

## Activity 3

**Create a cluster as an instance of the *Threat Actor* galaxy, defining the attacker "Estudiant del curs de ciberseguretat Montilivi".**

**Attach a screenshot of your new cluster.**

!["Add Cluster"](images/image21.png "Add Cluster")

!["Our new Cluster"](images/image22.png "Our new Cluster")

---

In order to use this new custer, we must publish it.


Publish is not a immediate action, it may take a few minutes.

Now, we add this cluster to the created event. List events, select yours and edit it. Add a cluster MISP, *Threat Actor*, and then start typing the name of your cluster until you see it.

---

## Activity 4

**Attach a screenshot of your event from Montilivi's cluster that you just created.**

!["Add new cluster"](images/image23.png "Add new cluster")

Publish the event.

!["Published event 1"](images/image24.png "Published event 1")

!["Published event 2"](images/image25.png "Published event 2")