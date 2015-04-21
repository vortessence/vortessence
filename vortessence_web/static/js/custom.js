/**
 * Created by Beni Urech, beni@beniurech.ch on 4/22/14.
 */

$(document).ready(function () {

    $(".showdetails").click(function () {
        $(this).parent().next().next().toggle();
        return false;
    })

    $(".expand_mf").click(function () {
        $(this).parent().parent().next().next().next().toggle();
        return false;
    })

    $(".load_det_results").click(function (event) {
        event.preventDefault();
        var elem_id;
        var view;
        elem_id = $(this).attr("value");
        view = $(this).attr("view");
        var link = $(this);
        if (link.next().html()) {
            link.next().empty();
        } else {
            $.get('/ajax/' + view + '/' + elem_id, {}, function (data) {
                link.next().html(data);
            });
        }
    })

    $(".load-ajax-modal-btn").click(function (event) {
        event.preventDefault();
        var elem_id;
        var view;
        elem_id = $(this).attr("value");
        view = $(this).attr("view");
        $("#wl_modal_body").load('/ajax/' + view + '/' + elem_id, function (result) {
            $("#wl_modal").modal({show: true});
        });
    });

    $(".ajax-link").click(function (event) {
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

    $("#image_edit").click(function() {
        $("#desc_p").hide();
        $("#desc_form").show();
        $(this).hide();
    });

});