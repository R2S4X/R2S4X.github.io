---
layout: page
title: Writeups
permalink: /writeups/
---

{% for post in site.categories.writeup %}
   {% capture this_year %}{{ post.date | date: "%Y" }}{% endcapture %}

   {% if forloop.first %}
<h3>{{this_year}}</h3>
<ul>
   {% else %}
      {% if this_year != prev_year %}
</ul>
<h3>{{this_year}}</h3>
<ul>
      {% endif %}
   {% endif %}

<li><!--{{ post.date | date: "%b %-d, %Y" }} --> <a href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a></li>

   {% capture prev_year %}{{ post.date | date: "%Y" }}{% endcapture %}

   {% if forloop.last %}
</ul>
   {% endif %}
{% endfor %}
