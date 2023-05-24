---
layout: post
---
<!-- got idea from: https://github.com/jekyll/jekyll/issues/6166 -->
{% capture md %}

# Advisories

{% for advisory in site.posts %}
  {% if advisory.advisory_collection == page.advisory_tag %}
* [{{advisory.title}}]({{advisory.url}})
  {% endif %}
{% endfor %}

{% endcapture %}
{{ md | markdownify }}

{{ content }}