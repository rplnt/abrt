function delProblem() {
    var req = new XMLHttpRequest();
    function handleDel() {
        if ( req.readyState == 4 && req.status == 200 ) {
            window.location = "/problems/";
        }
    }
    req.onreadystatechange = handleDel;
    req.open("DELETE", document.location.href, true);
    req.send(null);
}
