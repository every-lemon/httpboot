"""The HTTP Boot app: policy-driven desktop administration in one window."""
import datetime
import json
from pathlib import Path
from client_agent import rpc


def main():
    import gi
    gi.require_version('Gtk','3.0')
    from gi.repository import Gtk,GLib,Gdk,Pango
    class Window(Gtk.Window):
        def __init__(self):
            super().__init__(title='HTTP Boot');self.set_default_size(1040,720);self.set_size_request(760,520)
            self.connect('delete-event',lambda window,event:(window.hide() or True))
            self.state={};self.logs=[];self.errors=[];self.mutations=[];self.refreshing=False;self.first_login_offered=False
            header=Gtk.HeaderBar(title='HTTP Boot');header.set_show_close_button(True);self.set_titlebar(header)
            self.connection=Gtk.Label(label='Connecting…');header.pack_end(self.connection)
            css=Gtk.CssProvider();css.load_from_data(b'.httpboot-warning {padding:10px; border-radius:6px; background-color:#fff0c2; color:#473b10;}')
            Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(),css,Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=12,margin=18);self.add(box)
            self.warning=Gtk.Label(label='Non-persistent apps will not save data',xalign=0)
            self.warning.set_line_wrap(True);self.warning.get_style_context().add_class('httpboot-warning');box.pack_start(self.warning,False,False,0)
            self.content=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=16);box.pack_start(self.content,True,True,0)
            self.notebook=Gtk.Stack();self.notebook.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
            sidebar=Gtk.StackSidebar();sidebar.set_stack(self.notebook);sidebar.set_size_request(150,-1)
            self.content.pack_start(sidebar,False,False,0);self.content.pack_start(self.notebook,True,True,0)
            self.pages={}
            for name in ('Overview','Updates','Persistence','Marketplace','Diagnostics','Printers','Settings'):
                page=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=10,margin=12)
                scroll=Gtk.ScrolledWindow();scroll.set_policy(Gtk.PolicyType.NEVER,Gtk.PolicyType.AUTOMATIC);scroll.add(page)
                self.notebook.add_titled(scroll,name,name);self.pages[name]=page
            self.overview=self.label(self.pages['Overview'],'Checking saved-data status…')
            self.save_rows=Gtk.ListStore(str,str,str,str)
            self.table(self.pages['Overview'],self.save_rows,('Folder','Status','Last verified','Details'))
            self.session_label=self.label(self.pages['Overview'],'Checking Server session…')
            self.power_status=self.label(self.pages['Overview'],'')
            self.save_now_button=self.button(self.pages['Overview'],'Save selected data now',lambda:self.background(lambda:rpc('save-now')))
            self.images=self.label(self.pages['Updates'],'Checking for the latest validated image…')
            self.button(self.pages['Updates'],'Check for updates',self.check_images)
            self.operation=self.label(self.pages['Updates'],'')
            self.progress=Gtk.ProgressBar();self.progress.set_show_text(True);self.pages['Updates'].pack_start(self.progress,False,False,0)
            self.prepare_button=self.button(self.pages['Updates'],'Prepare update',lambda:self.background(lambda:rpc('prepare-update')));self.mutations.append(self.prepare_button)
            self.retry_button=self.button(self.pages['Updates'],'Retry failed operation',lambda:self.background(lambda:rpc('retry-update')));self.mutations.append(self.retry_button)
            self.restart_button=self.button(self.pages['Updates'],'Restart into verified update',self.restart);self.mutations.append(self.restart_button)
            self.rules=self.label(self.pages['Persistence'],'Select a folder below to inspect its history or stop keeping it. SSH policy is administrator managed.')
            self.rule_rows=Gtk.ListStore(str,str);self.rule_table=self.table(self.pages['Persistence'],self.rule_rows,('Selected folder','What is kept'))
            self.rule_table.get_selection().connect('changed',self.select_rule)
            self.add_folder=self.button(self.pages['Persistence'],'Keep a home folder',self.folder)
            self.remove_path=Gtk.Entry();self.remove_path.set_placeholder_text('Selected relative folder to stop keeping')
            self.pages['Persistence'].pack_start(self.remove_path,False,False,0)
            self.remove=self.button(self.pages['Persistence'],'Stop keeping a folder',self.remove_rule)
            self.button(self.pages['Persistence'],'Show save history for this folder',self.history)
            self.save_history=self.label(self.pages['Persistence'],'')
            self.add_app=self.button(self.pages['Persistence'],'Keep a Flatpak app',self.app)
            self.label(self.pages['Persistence'],'App installation bundles contain verified app/runtime content. Additional downloads inside private app data are saved only with “Keep app and data”.')
            self.market_query=Gtk.Entry();self.market_query.set_placeholder_text('Search approved Flatpak applications')
            self.pages['Marketplace'].pack_start(self.market_query,False,False,0)
            self.button(self.pages['Marketplace'],'Search',self.market_search)
            self.market_results=Gtk.ComboBoxText();self.pages['Marketplace'].pack_start(self.market_results,False,False,0)
            self.market_status=self.label(self.pages['Marketplace'],'Applications are saved with their runtimes. Choose whether to keep private data at installation.')
            self.market_items=[]
            self.button(self.pages['Marketplace'],'Details and permissions',self.market_details)
            self.mutations.append(self.button(self.pages['Marketplace'],'Install or update selected app',self.market_install))
            self.mutations.append(self.button(self.pages['Marketplace'],'Uninstall selected app (retain saved data)',self.market_uninstall))
            self.report=self.label(self.pages['Diagnostics'],'No diagnostic action requested')
            self.button(self.pages['Diagnostics'],'Send diagnostic report',self.send_report)
            self.button(self.pages['Diagnostics'],'Copy logs',self.copy)
            self.button(self.pages['Diagnostics'],'Export report',self.export)
            self.log_text=Gtk.TextView();self.log_text.set_editable(False);self.log_text.set_monospace(True);self.log_text.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            log_scroll=Gtk.ScrolledWindow();log_scroll.set_min_content_height(240);log_scroll.add(self.log_text);self.pages['Diagnostics'].pack_start(log_scroll,True,True,0)
            self.printers=self.label(self.pages['Printers'],'')
            self.button(self.pages['Printers'],'Refresh printers and queue',self.refresh_printers)
            self.printer_name=Gtk.ComboBoxText();self.pages['Printers'].pack_start(self.printer_name,False,False,0)
            for name,operation in (('Set default printer','default'),('Print test page','test')):
                self.mutations.append(self.button(self.pages['Printers'],name,lambda operation=operation:self.print_action(operation)))
            self.job=Gtk.Entry();self.job.set_placeholder_text('Your print job number');self.pages['Printers'].pack_start(self.job,False,False,0)
            self.mutations.append(self.button(self.pages['Printers'],'Cancel job',self.cancel))
            self.settings=self.label(self.pages['Settings'],'')
            self.pending=self.button(box,'Encrypt pending work to approved media',lambda:self.background(lambda:rpc('pending-export'),lambda value:self.report.set_text(value['message'])))
            footer=Gtk.Box(spacing=8);box.pack_start(footer,False,False,0)
            self.power_buttons=[self.button(footer,'Restart…',lambda:self.power('reboot')),self.button(footer,'Shut down…',lambda:self.power('poweroff'))]
            self.button(footer,'Hide',self.hide)
            self.refresh();GLib.timeout_add_seconds(2,self.refresh)
        def label(self,page,text):
            label=Gtk.Label(label=text,xalign=0);label.set_line_wrap(True);label.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR);label.set_max_width_chars(85);label.set_selectable(True)
            page.pack_start(label,False,False,0);return label
        def button(self,page,title,callback):
            button=Gtk.Button(label=title);button.set_halign(Gtk.Align.START);button.connect('clicked',lambda _:self.run(callback));page.pack_start(button,False,False,0);return button
        def table(self,page,model,titles):
            view=Gtk.TreeView(model=model);view.set_headers_visible(True)
            for number,title in enumerate(titles):
                renderer=Gtk.CellRendererText();renderer.set_property('ellipsize',Pango.EllipsizeMode.END)
                column=Gtk.TreeViewColumn(title,renderer,text=number);column.set_resizable(True);column.set_expand(number==(3 if len(titles)==4 else 0))
                column.set_min_width(190 if number==0 else 220 if number==3 else 90)
                if number==0 and len(titles)==4:column.set_max_width(290)
                if number==3:renderer.set_property('wrap-width',320);renderer.set_property('wrap-mode',Pango.WrapMode.WORD_CHAR)
                view.append_column(column)
            if len(titles)==4:view.set_tooltip_column(3)
            scroll=Gtk.ScrolledWindow();scroll.set_policy(Gtk.PolicyType.AUTOMATIC,Gtk.PolicyType.AUTOMATIC)
            scroll.set_min_content_height(240);scroll.add(view);page.pack_start(scroll,True,True,0)
            return view
        def replace_rows(self,model,rows):
            # Keep selection and scroll position while polling; changing labels
            # must not rebuild the entire view every two seconds.
            for number,row in enumerate(rows):
                if number>=len(model):model.append(row)
                else:
                    for column,value in enumerate(row):
                        if model[number][column]!=value:model[number][column]=value
            while len(model)>len(rows):model.remove(model.get_iter_from_string(str(len(model)-1)))
        def select_rule(self,selection):
            model,row=selection.get_selected()
            if row is not None:self.remove_path.set_text(model[row][0])
        def background(self,work,done=None):
            import threading
            def execute():
                try:
                    value=work()
                    if done:GLib.idle_add(lambda:(done(value),False)[1])
                    GLib.idle_add(self.refresh)
                except Exception as error:
                    message=str(error)
                    GLib.idle_add(lambda:self.show_error(message))
            threading.Thread(target=execute,daemon=True).start()
        def show_error(self,message):
            self.errors=(self.errors+[datetime.datetime.now().astimezone().isoformat(timespec='seconds')+' '+message])[-100:]
            dialog=Gtk.MessageDialog(transient_for=self,modal=True,message_type=Gtk.MessageType.ERROR,buttons=Gtk.ButtonsType.CLOSE,text='HTTP Boot needs attention')
            dialog.format_secondary_text(message);dialog.run();dialog.destroy();return False
        def power(self,operation):
            verb='Restart' if operation=='reboot' else 'Shut down'
            if self.ask(verb+' this Client?', 'Quit database applications normally first. All selected data must save and Server sessions must release successfully before '+verb.lower()+'.'):
                self.background(lambda:rpc('power',operation=operation))
        def run(self,callback):
            try:callback()
            except Exception as error:self.show_error(str(error))
        def ask(self,title,text):
            dialog=Gtk.MessageDialog(transient_for=self,modal=True,message_type=Gtk.MessageType.QUESTION,buttons=Gtk.ButtonsType.OK_CANCEL,text=title)
            dialog.format_secondary_text(text);answer=dialog.run();dialog.destroy();return answer==Gtk.ResponseType.OK
        def text(self,title):
            dialog=Gtk.Dialog(title=title,transient_for=self,modal=True);dialog.add_buttons('Cancel',Gtk.ResponseType.CANCEL,'Continue',Gtk.ResponseType.OK)
            entry=Gtk.Entry();dialog.get_content_area().add(entry);dialog.show_all()
            answer=entry.get_text() if dialog.run()==Gtk.ResponseType.OK else None;dialog.destroy();return answer
        def apply_rules(self,rules):
            self.background(lambda:rpc('rules',rules=rules))
        def folder(self):
            dialog=Gtk.FileChooserDialog(title='Keep a home folder',transient_for=self,action=Gtk.FileChooserAction.SELECT_FOLDER)
            dialog.add_buttons('Cancel',Gtk.ResponseType.CANCEL,'Keep folder',Gtk.ResponseType.OK)
            dialog.set_current_folder(str(Path.home()))
            dialog.set_show_hidden(True)
            closed=Gtk.CheckButton(label='Application data: save only when this folder is not in use')
            dialog.set_extra_widget(closed);closed.show()
            try:
                if dialog.run()==Gtk.ResponseType.OK:
                    selected=Path(dialog.get_filename()).resolve(strict=True).relative_to(Path.home().resolve())
                    rule={'folder':str(selected),'mode':'closed-folder' if closed.get_active() else 'folder','source':None}
                    if closed.get_active():
                        process=self.text('Application executable name (for example, thunderbird)')
                        if not process:return
                        rule['process']=process
                    self.apply_rules(self.state['rules']+[rule])
            finally:dialog.destroy()
        def remove_rule(self):
            folder=self.remove_path.get_text()
            if not any(r['folder']==folder for r in self.state['rules']):raise ValueError('Select a configured persistence folder')
            if self.ask('Stop keeping this folder?', 'Future changes will remain only in RAM. Previous Server saves are retained.'):
                self.apply_rules([r for r in self.state['rules'] if r['folder']!=folder])
        def history(self):
            folder=self.remove_path.get_text()
            self.background(lambda:rpc('snapshot',route='history',value={'folder':folder}),lambda result:self.save_history.set_text('\n'.join(datetime.datetime.fromtimestamp(row['created']).astimezone().isoformat(timespec='seconds')+' — '+row['consistency'] for row in result['snapshots']) or 'No verified saves yet'))
        def first_login(self):
            if self.state.get('access')!='edit' or any(r['folder']!='.ssh' for r in self.state.get('rules',[])):return False
            dialog=Gtk.Dialog(title='Choose folders to keep',transient_for=self,modal=True)
            dialog.add_buttons('Skip',Gtk.ResponseType.CANCEL,'Keep selected',Gtk.ResponseType.OK)
            choices=[]
            for folder in ('Documents','Desktop','Downloads','workspace'):
                button=Gtk.CheckButton(label=folder);dialog.get_content_area().add(button);choices.append((folder,button))
            dialog.show_all()
            try:
                if dialog.run()==Gtk.ResponseType.OK:
                    self.apply_rules(self.state.get('rules',[])+[{'folder':name,'mode':'folder','source':None} for name,button in choices if button.get_active()])
            finally:dialog.destroy()
            return False
        def app(self,selected=None):
            app=selected['id'] if selected else self.text('Flatpak application ID')
            if not app:return
            from flatpak_content import APP
            if not APP.fullmatch(app):raise ValueError('Invalid application ID')
            source=selected['source'] if selected else self.text('Approved source URL: '+', '.join(self.state.get('sources',[])))
            if source not in self.state.get('sources',[]):raise ValueError('Choose an administrator-approved source')
            keep_data=self.ask('Keep app and data?','Choose OK to retain private app data and additional downloads. Cancel keeps the app only; private data resets at the next boot.')
            if not keep_data and not self.ask('Keep app only','The application and its runtime are kept. Private app data and additional downloads reset at the next boot. Enable this mode?'):return
            rules=[rule for rule in self.state['rules'] if rule['folder'] not in ('.local/share/httpboot/flatpak-bundles/'+app,'.var/app/'+app)]+[{'folder':'.local/share/httpboot/flatpak-bundles/'+app,'mode':'app-only','source':source}]
            if keep_data:rules.append({'folder':'.var/app/'+app,'mode':'app-and-data','source':source})
            import threading
            def install_app():
                try:
                    from flatpak_content import install
                    # Authorize persistence before downloading application content.
                    rpc('rules',rules=rules)
                    install(app,source)
                    from flatpak_content import export
                    from persistence_v2 import Saver
                    import os
                    export(Path.home(),app,source,self.state.get('sources',[]))
                    saver=Saver(Path.home(),Path('/run/httpboot-v2/users')/str(os.getuid())/'cache.sqlite3',
                                lambda route,value:rpc('snapshot',route=route,value=value))
                    saver.save(next(rule for rule in rules if rule['folder']=='.local/share/httpboot/flatpak-bundles/'+app))
                    GLib.idle_add(lambda:self.market_status.set_text(app+': app and runtime verified and saved for next boot.'))
                    GLib.idle_add(self.refresh)
                except Exception as error:
                    message=str(error)
                    GLib.idle_add(lambda:self.run(lambda:(_ for _ in ()).throw(ValueError(message))))
            threading.Thread(target=install_app,daemon=True).start()
        def market_selected(self):
            index=self.market_results.get_active()
            if index<0 or index>=len(self.market_items):raise ValueError('Select an application first')
            return self.market_items[index]
        def market_job(self,work,done):
            import threading
            def execute():
                try:
                    value=work();GLib.idle_add(done,value)
                except Exception as error:
                    message=str(error)
                    GLib.idle_add(lambda:self.market_status.set_text('Operation incomplete: '+message+'. Installed content may exist only in this session until a verified save succeeds.'))
            threading.Thread(target=execute,daemon=True).start()
        def market_search(self):
            from flatpak_content import search
            query=self.market_query.get_text();sources=list(self.state.get('sources',[]))
            self.market_status.set_text('Searching approved repositories…')
            def completed(items):
                self.market_items=items;self.market_results.remove_all()
                for item in items:self.market_results.append_text(item['name']+' — '+item['id'])
                if items:self.market_results.set_active(0)
                self.market_status.set_text(str(len(items))+' matching applications')
            self.market_job(lambda:search(query,sources),completed)
        def market_details(self):
            from flatpak_content import details
            item=self.market_selected()
            self.market_job(lambda:details(item['id'],item['source']),self.market_status.set_text)
        def market_install(self):self.app(self.market_selected())
        def market_uninstall(self):
            from flatpak_content import uninstall
            item=self.market_selected()
            if not self.ask('Uninstall '+item['name']+'?', 'Saved private data will remain on the Server.'):return
            folder='.local/share/httpboot/flatpak-bundles/'+item['id']
            rules=[r for r in self.state['rules'] if r['folder']!=folder]
            def remove():
                rpc('rules',rules=rules);return uninstall(item['id'])
            self.market_job(remove,lambda _:self.market_status.set_text('Uninstalled; saved private data retained.'))
        def restart(self):
            if self.ask('Restart into the verified update?', 'Close applications first. Selected folders for all logged-in users must save successfully. Restart remains your choice.'):
                self.background(lambda:rpc('restart-update'))
        def check_images(self):
            import threading
            def check():
                try:
                    values=rpc('images')['images']
                    message='Latest validated image: '+values[0]['release'] if values else 'No validated image has been published.'
                except Exception as error:message='Activation Server Error: '+str(error)
                GLib.idle_add(self.images.set_text,message)
            threading.Thread(target=check,daemon=True).start()
        def send_report(self):
            self.background(lambda:rpc('diagnostics'),lambda _:self.report.set_text('The Server received the redacted diagnostic report.'))
        def copy(self):Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text('\n'.join(self.logs[-200:]),-1)
        def export(self):
            dialog=Gtk.FileChooserDialog(title='Export HTTP Boot report',transient_for=self,action=Gtk.FileChooserAction.SAVE)
            dialog.add_buttons('Cancel',Gtk.ResponseType.CANCEL,'Save',Gtk.ResponseType.OK);dialog.set_current_name('httpboot-report.txt');dialog.set_do_overwrite_confirmation(True)
            try:
                if dialog.run()==Gtk.ResponseType.OK:Path(dialog.get_filename()).write_text('\n'.join(self.logs[-200:])+'\n')
            finally:dialog.destroy()
        def refresh_printers(self):
            self.background(lambda:rpc('printers'),self.render_printers)
        def render_printers(self,values):
            chosen=self.printer_name.get_active_id();self.printer_name.remove_all();lines=[]
            for printer in values['printers']:
                name=printer['name'];label=name+(' (default)' if name==values['default'] else '')
                self.printer_name.append(name,label)
                lines.append(label+' — '+{3:'Ready',4:'Printing',5:'Stopped'}.get(printer.get('printer-state'),'Unavailable'))
            if not self.printer_name.set_active_id(chosen or values['default'] or ''):self.printer_name.set_active(0)
            jobs=values['jobs']
            lines.append('\nQueue: '+('Empty' if not jobs else ''))
            for job in jobs:lines.append('Job '+str(job['id'])+' — '+{3:'Waiting',4:'Held',5:'Printing',6:'Stopped',7:'Canceled',8:'Failed',9:'Completed'}.get(job.get('job-state'),'Unknown'))
            self.printers.set_text('\n'.join(lines) if values['printers'] else 'No printers discovered. Connect an IPP printer and refresh.')
        def print_action(self,operation):
            name=self.printer_name.get_active_id();self.background(lambda:rpc('printers',operation=operation,printer=name),lambda _:self.refresh_printers())
        def cancel(self):
            job=int(self.job.get_text());self.background(lambda:rpc('printers',operation='cancel',job=job),lambda _:self.refresh_printers())
        def refresh(self):
            if self.refreshing:return True
            self.refreshing=True
            import threading
            def fetch():
                try:
                    state=rpc('state');GLib.idle_add(self.render_state,state)
                except Exception as error:GLib.idle_add(self.state_error,str(error))
            threading.Thread(target=fetch,daemon=True).start()
            return True
        def state_error(self,message):
            self.refreshing=False;self.connection.set_text('Connection unavailable')
            self.warning.set_text('HTTP Boot service unavailable: '+message+'\nCurrent work remains in RAM; retrying automatically.')
            return False
        def render_state(self,state):
            self.refreshing=False;self.state=state;access=state['access']
            if not self.first_login_offered:self.first_login_offered=True;GLib.idle_add(self.first_login)
            image=state.get('image_status',{});operation=state.get('operation',{});power=state.get('power',{})
            self.connection.set_text('Client '+str(image.get('current') or 'online'))
            self.images.set_text(image.get('message','Checking for the latest validated image…'))
            pending=sum(v.get('phase')=='pending' for k,v in state.get('status',{}).items() if k!='general')
            self.warning.set_text((str(pending)+(' selected folder has' if pending==1 else ' selected folders have')+' pending RAM changes. ' if pending else '')+state['warning'])
            if image.get('state')=='error':self.warning.set_text(self.warning.get_text()+'\n'+image['message'])
            self.operation.set_text(operation.get('message','No update is running'))
            self.logs=([datetime.datetime.fromtimestamp(row['time']).astimezone().isoformat(timespec='seconds')+' '+row['message'] for row in operation.get('logs',[])]+self.errors)[-200:]
            self.log_text.get_buffer().set_text('\n'.join(self.logs) or 'No operation logs yet.')
            total=operation.get('bytes_total',0);done=operation.get('bytes_done',0);phase=operation.get('phase','idle')
            fraction=min(1,done/total) if total else operation.get('percent',0)/100
            if phase=='ready-to-restart':fraction=1
            self.progress.set_fraction(fraction)
            if total:
                eta=operation.get('eta_seconds');remaining=f'{eta:.0f}s remaining' if eta is not None else 'Estimating remaining time'
                text=f"{done/1048576:.1f} / {total/1048576:.1f} MiB · {operation.get('bytes_per_second',0)/1048576:.1f} MiB/s · {operation.get('elapsed_seconds',0)}s elapsed · {remaining}"
            else:text={'ready-to-restart':'Verified and ready to restart','applied':'This update is running','idle':'No update in progress'}.get(phase,phase.replace('-',' ').capitalize())
            self.progress.set_text(text)
            self.content.set_visible(access!='none');self.pending.set_visible(state.get('pending_media_available',False))
            busy=power.get('state')=='running'
            self.save_now_button.set_sensitive(not busy)
            for button in self.power_buttons:button.set_sensitive(not busy and operation.get('state')!='running')
            edit=access=='edit' and not busy
            for widget in (self.add_folder,self.add_app,self.remove):widget.set_sensitive(edit)
            for button in self.mutations:button.set_sensitive(edit)
            self.prepare_button.set_sensitive(edit and operation.get('state')!='running' and image.get('state')=='available')
            self.retry_button.set_sensitive(edit and operation.get('state')=='failed')
            self.restart_button.set_sensitive(edit and phase=='ready-to-restart')
            statuses=state.get('status',{});verified=sum(v.get('phase')=='verified' for k,v in statuses.items() if k!='general')
            self.overview.set_text(f'{verified} selected folders verified · {pending} pending. Previous verified snapshots remain on the Server.')
            save_rows=[]
            names={r['folder'] for r in state.get('rules',[])}|set(statuses)
            for folder in sorted(names):
                value=statuses.get(folder,{});status={'verified':'Verified','transferring':'Saving','pending':'Pending','restoring':'Restoring'}.get(value.get('phase'),'Waiting')
                stamp=datetime.datetime.fromtimestamp(value['updated']).astimezone().strftime('%H:%M:%S') if value.get('updated') else '—'
                save_rows.append(('App data + sign-in save' if folder=='general' else folder,status,stamp,value.get('message','')))
            self.replace_rows(self.save_rows,save_rows)
            rule_rows=[]
            for rule in state.get('rules',[]):
                mode={'folder':'Folder','closed-folder':'Data after app closes','app-only':'App and runtime only','app-and-data':'App and private data'}.get(rule['mode'],rule['mode'])
                rule_rows.append((rule['folder'],mode))
            self.replace_rows(self.rule_rows,rule_rows)
            health=state.get('session_health',{})
            self.session_label.set_text(health.get('message','Checking Server session heartbeat…'))
            self.power_status.set_text(power.get('message',''))
            self.settings.set_text('SSH key persistence: '+('enabled (administrator managed)' if state.get('ssh_persistence') else 'disabled')+'\nServer app permission: '+access+'\nApproved sources: '+', '.join(state.get('sources',[]))+'\nDisconnected session grace: 15 minutes since the last heartbeat')
            return False
    window=Window();window.show_all();window.refresh();GLib.idle_add(window.first_login);Gtk.main()

if __name__=='__main__':main()
