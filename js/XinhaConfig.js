xinha_editors=null;
xinha_init=null;
xinha_config=null;
xinha_plugins=null;
xinha_init=xinha_init?xinha_init:function(){
xinha_editors=xinha_editors?xinha_editors:["editorArea"];
xinha_plugins=xinha_plugins?xinha_plugins:["CharacterMap","CharCounter","GetHtml"];
if(!Xinha.loadPlugins(xinha_plugins,xinha_init)){return}
xinha_config=xinha_config?xinha_config():new Xinha.Config();
xinha_config.showLoading=true;
xinha_config.autofocus="editorArea";
xinha_config.toolbar=[
["popupeditor"],
["separator","formatblock","fontname","fontsize","bold","italic","underline","strikethrough"],
["separator","forecolor","hilitecolor","textindicator"],
["separator","subscript","superscript"],
["linebreak","separator","justifyleft","justifycenter","justifyright","justifyfull"],
["separator","insertorderedlist","insertunorderedlist","outdent","indent"],
["separator","inserthorizontalrule","createlink","insertimage","inserttable"],
["linebreak","separator","undo","redo","selectall","print"],
(Xinha.is_gecko?[]:["cut","copy","paste","overwrite","saveas"]),
["separator","killword","clearfonts","removeformat","toggleborders","splitblock","lefttoright","righttoleft"],
["separator","htmlmode","showhelp","about"]];
//xinha_config.pageStyleSheets=["http://croqqq.pythonanywhere.com/"+"js/Xinha.style.css"];
xinha_config.pageStyleSheets=["http://localhost:333/"+"js/Xinha.style.css"];
xinha_editors=Xinha.makeEditors(xinha_editors,xinha_config,xinha_plugins);
Xinha.startEditors(xinha_editors)};
Xinha.addOnloadHandler(xinha_init);