"""Minimal tabbed recovery browser. Profiles and downloads live only in RAM."""
import sys

def main():
    import gi
    gi.require_version('Gtk','3.0');gi.require_version('WebKit2','4.1')
    from gi.repository import Gtk,WebKit2
    window=Gtk.Window(title='HTTP Boot recovery browser');window.set_default_size(1000,700)
    box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=4);window.add(box)
    tabs=Gtk.Notebook();tabs.set_scrollable(True)
    row=Gtk.Box(spacing=4);address=Gtk.Entry();address.set_placeholder_text('Enter an address')
    back=Gtk.Button(label='Back');new=Gtk.Button(label='New tab')
    row.pack_start(back,False,False,0);row.pack_start(address,True,True,0);row.pack_start(new,False,False,0)
    box.pack_start(row,False,False,0);box.pack_start(tabs,True,True,0)
    context=WebKit2.WebContext.new_ephemeral()
    def add(url='about:blank'):
        view=WebKit2.WebView.new_with_context(context)
        view.connect('notify::uri',lambda web,_:address.set_text(web.get_uri() or ''))
        tabs.append_page(view,Gtk.Label(label='Tab '+str(tabs.get_n_pages()+1)))
        view.show();tabs.set_current_page(tabs.get_n_pages()-1);view.load_uri(url)
    def navigate(entry):
        value=entry.get_text().strip()
        if '://' not in value and value!='about:blank':value='https://'+value
        if not value.startswith(('https://','http://','about:')):return
        tabs.get_nth_page(tabs.get_current_page()).load_uri(value)
    address.connect('activate',navigate)
    new.connect('clicked',lambda _:add())
    back.connect('clicked',lambda _:tabs.get_nth_page(tabs.get_current_page()).go_back())
    window.connect('destroy',Gtk.main_quit);add();window.show_all();Gtk.main()

if __name__=='__main__':main()
