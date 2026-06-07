from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_patcher():
    patcher_path = Path(__file__).resolve().parents[2] / "patches" / "apply_template_patches.py"
    spec = importlib.util.spec_from_file_location("dojo_epss_template_patcher", patcher_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _findings_template() -> str:
    return """
<table>
    <thead>
        <tr>
            <th scope="col">
                {% trans "Known Exploited" %}
            </th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
                {{ finding.known_exploited|yesno|capfirst }}
            </td>
        </tr>
    </tbody>
</table>
<script>
columns = [
    { "data": "known_exploited", },
]
</script>
"""


def _bootstrap_base() -> str:
    return """
<ul class="nav" id="side-menu">
    {% block sidebar-items %}
        <li><a href="{% url 'dashboard' %}">Dashboard</a></li>
        {% if "auth.view_user"|has_configuration_permission:request %}
            <li>
                <a href="{% url 'users' %}">Users</a>
                <ul class="nav nav-second-level">
                    <li><a href="{% url 'users' %}">Users</a></li>
                    {# Pro restores the Groups link by overriding this block. #}
                    {% block groups_submenu_link %}{% endblock %}
                </ul>
            </li>
        {% endif %}
    {% endblock %}
    {% block support-tab %}
        <li><a href="{% url 'support' %}">Upgrade</a></li>
    {% endblock %}
</ul>
"""


def _tailwind_base_with_bad_insert() -> str:
    return """
<nav class="flex-1 py-3 space-y-0.5" aria-label="Main navigation">
    {% block sidebar-items %}
    <a href="{% url 'dashboard' %}" class="flex items-center gap-3 px-4 py-2 text-gray-300 hover:text-white hover:bg-white/10 transition-colors">Dashboard</a>
    <div x-data="{ open: false }">
        <a href="{% url 'users' %}" @click.prevent="open = !open"
           class="flex items-center gap-3 px-4 py-2 text-gray-300 hover:text-white hover:bg-white/10 transition-colors cursor-pointer">
            <span class="flex-1 truncate">{% trans "Users" %}</span>
        </a>
        <div x-show="open" x-transition.duration.200ms x-cloak class="overflow-hidden bg-black/10">
            <a href="{% url 'users' %}" class="block py-1.5 pl-12 pr-4 text-sm text-gray-400 hover:text-white hover:bg-white/10">{% trans "Users" %}</a>
            {# Pro restores the Groups link by overriding this block. #}
                                        {# dojo_epss: EPSS sidebar entry - purely additive #}
                                        {% include "dojo_epss/partials/sidebar_menu.html" %}
            {% block groups_submenu_link %}{% endblock %}
        </div>
    </div>
    <div x-data="{ open: false }">
        <a href="#" @click.prevent="open = !open"
           class="flex items-center gap-3 px-4 py-2 text-gray-300 hover:text-white hover:bg-white/10 transition-colors cursor-pointer">Configuration</a>
    </div>
    {% endblock sidebar-items %}
    {% block support-tab %}
    <a href="{% url 'support' %}" class="flex items-center gap-3 px-4 py-2 text-gray-300 hover:text-white hover:bg-white/10 transition-colors">Upgrade</a>
    {% endblock %}
</nav>
"""


def test_patcher_places_sidebar_in_old_bootstrap_template(tmp_path):
    patcher = _load_patcher()
    _write(tmp_path / "dojo/templates/base.html", _bootstrap_base())
    _write(tmp_path / "dojo/templates/dojo/findings_list_snippet.html", _findings_template())

    assert patcher.main([str(tmp_path)]) == 0

    rendered = (tmp_path / "dojo/templates/base.html").read_text(encoding="utf-8")
    assert rendered.count('include "dojo_epss/partials/sidebar_menu.html"') == 1
    assert 'sidebar_menu_tailwind.html' not in rendered
    assert rendered.index('include "dojo_epss/partials/sidebar_menu.html"') < rendered.index("{% block support-tab %}")

    users_submenu = rendered[
        rendered.index("{# Pro restores the Groups link")
        : rendered.index("{% block groups_submenu_link %}")
    ]
    assert "dojo_epss" not in users_submenu


def test_patcher_moves_bad_tailwind_insert_to_top_level(tmp_path):
    patcher = _load_patcher()
    _write(tmp_path / "dojo/templates/base.html", _tailwind_base_with_bad_insert())
    _write(tmp_path / "dojo/templates/dojo/findings_list_snippet.html", _findings_template())

    assert patcher.main([str(tmp_path)]) == 0

    rendered = (tmp_path / "dojo/templates/base.html").read_text(encoding="utf-8")
    assert 'include "dojo_epss/partials/sidebar_menu.html"' not in rendered
    assert rendered.count('include "dojo_epss/partials/sidebar_menu_tailwind.html"') == 1
    assert rendered.index('include "dojo_epss/partials/sidebar_menu_tailwind.html"') < rendered.index("{% endblock sidebar-items %}")

    users_submenu = rendered[
        rendered.index("{# Pro restores the Groups link")
        : rendered.index("{% block groups_submenu_link %}")
    ]
    assert "dojo_epss" not in users_submenu


def test_patcher_updates_and_reverses_both_ui_trees(tmp_path):
    patcher = _load_patcher()
    _write(tmp_path / "dojo/templates/base.html", _tailwind_base_with_bad_insert())
    _write(tmp_path / "dojo/templates_classic/base.html", _bootstrap_base())
    _write(tmp_path / "dojo/templates/dojo/findings_list_snippet.html", _findings_template())
    _write(tmp_path / "dojo/templates_classic/dojo/findings_list_snippet.html", _findings_template())

    assert patcher.main([str(tmp_path)]) == 0

    tailwind = (tmp_path / "dojo/templates/base.html").read_text(encoding="utf-8")
    classic = (tmp_path / "dojo/templates_classic/base.html").read_text(encoding="utf-8")
    assert 'sidebar_menu_tailwind.html' in tailwind
    assert 'sidebar_menu.html' in classic
    assert "finding_epss_update_th.html" in (tmp_path / "dojo/templates/dojo/findings_list_snippet.html").read_text(encoding="utf-8")
    assert "finding_epss_update_th.html" in (tmp_path / "dojo/templates_classic/dojo/findings_list_snippet.html").read_text(encoding="utf-8")

    assert patcher.main(["--reverse", str(tmp_path)]) == 0

    for relative in (
        "dojo/templates/base.html",
        "dojo/templates_classic/base.html",
        "dojo/templates/dojo/findings_list_snippet.html",
        "dojo/templates_classic/dojo/findings_list_snippet.html",
    ):
        rendered = (tmp_path / relative).read_text(encoding="utf-8")
        assert "dojo_epss/partials/sidebar_menu" not in rendered
        assert "finding_epss_update" not in rendered
