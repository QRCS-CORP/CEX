

    $(document).ready(function()
    {
      var bardata     = GetBarChartData();

      var title       = bardata.title;  
      var itemNames   = bardata.itemNames;
      var itemColours = bardata.itemColours;
      var itemValues  = bardata.itemValues;
      var ItemDescs   = bardata.ItemDescs;

      var tickLabels = [""];


      // POINTS: What we really want here is:
      // ID (value) or Category (value)
      //
      var pointtext= [];
      for (x = 0; x < itemNames.length; ++x)
      {
        pointtext.push("<div align=center>" + itemNames[x] + "<br/>(" + itemValues[x] + ")</div>");
      }

     
      // LEGENDS: What we really want here is:
      // legend = value x ID (category - issue desc) [for Issue ID charts)
      // legend = value x Category (for category charts) 
      var legendtext= [];
      for (x = 0; x < itemNames.length; ++x)
      {
        var text = itemValues[x] + " x " + itemNames[x];
        if (ItemDescs[x])
        {
          text += (" " + ItemDescs[x]);
        }
        legendtext.push(text);
      }

      var labeltext = legendtext;

      var bardata = [];
      
      for (x = 0; x < itemValues.length; ++x)
      {
        var array = new Array();
        array[0] = itemValues[x];
        bardata.push(array);
      }


      var serieslabels = [];
      for (x = 0; x < itemValues.length; ++x)
      {
        var pointlabel = 
        {
            pointLabels:
            {
              labels: [pointtext[x]]
            }
        };

        serieslabels.push(pointlabel);
      }


      var plot1 = $.jqplot('issue_id_chart', bardata,
      {
        title: "",
      
        seriesDefaults:
        {
          renderer: $.jqplot.BarRenderer,
          pointLabels: { show:true, escapeHTML:false  }
        },
      
        seriesColors: itemColours,
      
        series: serieslabels,
      
        axes:
        {
          xaxis:
          {
            renderer: $.jqplot.CategoryAxisRenderer,
            ticks: tickLabels
          }
        },
      
        legend:
        {
          show: true,
          location: 'e',
          placement: 'outsideGrid',
          labels: legendtext
        }
      });


      $(window).resize(function()
      {
          plot1.replot( { resetAxes: true } );
      });
            
    });