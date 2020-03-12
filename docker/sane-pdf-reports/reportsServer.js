/* eslint-disable */
const page = require('webpage').create();
const system = require('system');
const fs = require('fs');
const PAGE_SIZES = {
  A4: 'A4',
  A3: 'A3',
  Letter: 'letter',
  A5: 'A5'
};

const PAGE_ORIENTATION = {
  portrait: 'portrait',
  landscape: 'landscape'
};

function getPageSize(pageSize) {
  switch (pageSize) {
    case PAGE_SIZES.A3:
      return { width: '297mm', height: '420mm' };
    case PAGE_SIZES.A5:
      return { width: '148mm', height: '210mm' };
    case PAGE_SIZES.Letter:
      return { width: '216mm', height: '279mm' };
    case PAGE_SIZES.A4:
    default:
      return { width: '210mm', height: '297mm' };
  }
}

function getPageSizeByOrientation(pageSize, orientation) {
  const size = getPageSize(pageSize);
  if (orientation && orientation === PAGE_ORIENTATION.landscape) {
    const h = size.height;
    const w = size.width;
    return { width: h, height: w };
  }
  return size;
}

phantom.onError = function(msg, trace) {
  const msgStack = ['PHANTOMJS ERROR: ' + msg];
  if (trace && trace.length) {
    msgStack.push('TRACE:');
    trace.forEach(function(t) {
      msgStack.push(' -> ' + (t.file || t.sourceURL) + ': ' + t.line + (t.function ? ' (in function ' + t.function +')' : ''));
    });
  }
  console.error(msgStack.join('\n'));
  phantom.exit(1);
};


console.log('Starting report server');
console.log('Using PhantomJS version ' +
    phantom.version.major + '.' +
    phantom.version.minor + '.' +
    phantom.version.patch
);
console.log('Agent details: ' +
    page.settings.userAgent
);

if (system.args.length < 2) {
  console.log('Usage: reportServer.js <data file> [<output file> <dist folder> <portrait/landscape> <resourceTimeout> <type> <headerLeftImage> <headerRightImage>]');
  phantom.exit(1);
}

const dataFile = system.args[1];
const outputFile = system.args[2];
const distDir = system.args[3];
const orientation = system.args[4] || PAGE_ORIENTATION.portrait;
const resourceTimeout = system.args[5];
const reportType = system.args[6] || 'pdf';
var headerLeftImage = system.args[7] || '';
const headerRightImage = system.args[8] || '';
const pageSize = system.args[10] || PAGE_SIZES.Letter;
const disableHeaders = system.args[11] === true || system.args[11] === "true";
page.settings.resourceTimeout = resourceTimeout ? Number(resourceTimeout) : 4000;

if (headerLeftImage && headerLeftImage.indexOf('data:image') === -1) {
  try {
    const headerLeftImageContent = fs.read(headerLeftImage);
    headerLeftImage = headerLeftImageContent;
  } catch (ex) {
    // ignored
  }
}
console.log(system.args);

const distFolder = distDir || (fs.absolute(".") + '/dist');

const indexHtml = fs.read(distFolder + '/index.html');
const afterTypeReplace =
  indexHtml
    .replace('\'{report-type}\'', JSON.stringify(reportType))
    .replace('{report-header-image-left}', headerLeftImage)
    .replace('{report-header-image-right}', headerRightImage);

const loadedData = fs.read(dataFile);

// $ is a special character in string replace, see here: https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/String/replace#Specifying_a_string_as_a_parameter
const finalHtmlData = afterTypeReplace.replace('\'{report-data-to-replace}\'', loadedData.replace(/\$/g, '$$$$'));

const date = Date.now();

const tmpReportName = outputFile ? (outputFile.substring(outputFile.lastIndexOf('/'), outputFile.lastIndexOf('.')) + '.html') : 'reportTmp-' + date + '.html';
fs.write(distFolder + '/' + tmpReportName, finalHtmlData, 'w');

console.log('HTML template was created: ' + distFolder + '/' + tmpReportName);

const baseUrl = distFolder.indexOf('/') === 0 ? distFolder : fs.absolute(".") + '/' + distFolder;

try {
  page.paperSize = {
    format: pageSize, // 'A3', 'A4', 'A5', 'Legal', 'Letter', 'Tabloid'
    orientation: orientation, // portrait / landscape
    header: {
      height: !disableHeaders ? "1.3cm" : '',
      contents: phantom.callback(function() {
        return !disableHeaders ? "" +
          "<div style='" +
            "background-color: #fcfcfc;" +
            "height: 200px;" +
            "font-size: 10px;" +
            "margin-top: -7px;" +
            "margin-right: -10px;" +
            "margin-left: -10px;" +
            "padding-top: 13px;" +
            "padding-right: 20px;" +
            "padding-left: 20px;'" +
          ">" +
            "<div style='text-align: left; float: left'>" +
              "<img src=\""+headerLeftImage+"\" height='20px' />" +
            "</div>" +
            "<div style='text-align: right; float: right'>" +
              "<img src=\""+headerRightImage+"\" height='20px' />" +
            "</div>" +
          "</div>" : '';
      })
    },
    footer: {
      height: "0.9cm",
      contents: phantom.callback(function(pageNum, numPages) {
        return "" +
          "<div style='" +
            "background-color: #fcfcfc;" +
            "font-size: 10px;" +
            "text-align: center;" +
            "border-top: 1px solid #d6d6d6;" +
            "color: #8e8e8e;" +
            "font-family: \"Source Sans Pro\";" +
            "margin-top: -7px;" +
            "margin-bottom: 10px;" +
            "padding-top: 7px;'" +
          ">" +
          headerLeftImage && disableHeaders ? '<img style="float: left; height: 10px; margin: 0 10px;width: auto;" src='+ headerLeftImage +' />' : '' +
          headerRightImage && disableHeaders ? '<img style="float: right;height: 10px; margin: 0 10px;width: auto;" src='+ headerRightImage +' />' : '' +
            "<span>" +
            "" + pageNum + " / " + numPages + "" +
            "</span>" +
          "</div>";
      })
    }
  };

  page.onLoadFinished = function (status) {
    if (status !== "success") {
      console.log("Page was not loaded.");
      phantom.exit(1);
    }

    if (reportType === 'pdf') {
      setTimeout(function () {
        if (page.render(outputFile || distFolder + '/report-' + date + '.pdf', {quality: 100})) {
          console.log("PDF report was generated successfully.");
          try {
            page.close();
            fs.remove(distFolder + '/' + tmpReportName);
          } catch (ignored) {
            // do nothing
          }
        } else {
          console.log("Failed to generate PDF report.");
        }
        phantom.exit();
      }, 5000); // time out is needed for all animation to be finished
    }
  };

  page.open('file://' + baseUrl + '/' + tmpReportName, function (status) {
    console.log("Read report page status: " + status);

    if (status === "success") {
      const dimensions = getPageSizeByOrientation(pageSize, orientation);
      page.evaluate(function(dimensions) {
        // fix phantomJS bug (https://github.com/marcbachmann/node-html-pdf/issues/198)
        if (reportType === 'pdf') {
          document.querySelector('html').style.zoom = 0.75;
          document.querySelector('body').style.width = 'calc(' + dimensions.width + ')';
          document.querySelector('body').style.height = 'calc(' + dimensions.height + ')';
        }
      }, dimensions);
      switch (reportType) {
        case 'csv':
          const csvData = page.evaluate(function() {
            return document.csvData;
          });
          if (csvData) {
            fs.write(outputFile || distFolder + '/report-' + date + '.csv', csvData, 'w');
            fs.remove(distFolder + '/' + tmpReportName);
            console.log("CSV report was generated successfully.");
          } else {
            console.log("Failed to generate CSV report.");
          }
          phantom.exit();
          break;
        case 'html':
          console.log("HTML report was generated successfully.");
          phantom.exit();
      }
    } else {
      console.log("Cannot open report page.");
      phantom.exit(1);
    }
  });
} catch (ex) {
  console.log("Error when opening html report: " + ex);
  phantom.exit(1);
}
