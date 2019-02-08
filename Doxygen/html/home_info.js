var myCircle1 = Circles.create({
    id:         'circles-1',
    radius:     60,
    value:      43,
    maxValue:   100,
    width:      5,
    text:       function(value){return value + '%';},
    colors:     ['rgba(255,255,255,0.3)', '#fff'],
    duration:   1000,
    wrpClass:   'circles-wrp',
    textClass:  'circles-text'
});

var myCircle2 = Circles.create({
    id:         'circles-2',
    radius:     60,
    value:      60,
    maxValue:   100,
    width:      5,
    text:       function(value){return value + '%';},
    colors:     ['rgba(255,255,255,0.3)', '#fff'],
    duration:   1000,
    wrpClass:   'circles-wrp',
    textClass:  'circles-text'
});

var myCircle3 = Circles.create({
    id:         'circles-3',
    radius:     60,
    value:      80,
    maxValue:   100,
    width:      5,
    text:       function(value){return value + '%';},
    colors:     ['rgba(255,255,255,0.3)', '#fff'],
    duration:   1000,
    wrpClass:   'circles-wrp',
    textClass:  'circles-text'
});

var myCircle4 = Circles.create({
    id:         'circles-4',
    radius:     60,
    value:      100,
    maxValue:   100,
    width:      5,
    text:       function(value){return value + '%';},
    colors:     ['rgba(255,255,255,0.3)', '#fff'],
    duration:   1000,
    wrpClass:   'circles-wrp',
    textClass:  'circles-text'
});

$(document).ready(function(){
    $('#latest-works').bxSlider({
        hideControlOnEnd: true,
        minSlides: 2,
        maxSlides: 4,
        slideWidth: 275,
        slideMargin: 10,
        pager: false,
        nextSelector: '#bx-next4',
        prevSelector: '#bx-prev4',
        nextText: '>',
        prevText: '<',
    });

    $('#home-block').bxSlider({
        hideControlOnEnd: true,
        minSlides: 1,
        maxSlides: 1,

        pager: false,
        nextSelector: '#bx-next5',
        prevSelector: '#bx-prev5',
        nextText: '>',
        prevText: '<',
    });
});