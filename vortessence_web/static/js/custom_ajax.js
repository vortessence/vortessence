/**
 * Created by Beni Urech, beni@beniurech.ch on 4/22/14.
 */

$(document).ready(function () {
    $(".ajax-link-fromajax").click(function (event) {
        event.preventDefault();
        var elem_id;
        var view;
        var target;
        elem_id = $(this).attr("value");
        view = $(this).attr("view");
        target = $(this).attr("href");
        if ($(target).is("td")) {
            $(target).parent().toggle();
        }
        if ($(target).html().length == 0) {
            $(target).html("Loading...");
            $.get('/ajax/' + view + '/' + elem_id, {}, function (data) {
                $(target).html(data);
            });
        }
    });
});