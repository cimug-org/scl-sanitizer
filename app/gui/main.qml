import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts

ApplicationWindow {
    width: 700
    height: 420
    visible: true
    title: "SCL Sanitizer"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 18

        Label {
            text: "SCL Sanitizer"
            font.pixelSize: 28
            font.bold: true
        }

        RowLayout {
            spacing: 12
            TextField {
                id: fileField
                Layout.fillWidth: true
                placeholderText: "Choose an SCL file"
                readOnly: true
            }

            Button {
                text: "Browse"
                onClicked: fileDialog.open()
            }
        }

        CheckBox {
            id: hashSeedCheck
            text: "Use hash-based seed"
        }

        RowLayout {
            visible: !hashSeedCheck.checked
            spacing: 12
            Label { text: "Seed:" }
            SpinBox {
                id: seedBox
                from: 0
                to: 2147483647
                value: 12345
            }
        }

        Button {
            text: "Sanitize"
            onClicked: {
                const path = fileField.text
                if (!path) {
                    status.text = "Please select a file."
                    return
                }

                try {
                    const result = SanitizerBridge.sanitize_file(path, hashSeedCheck.checked, seedBox.value)
                    status.text = "Success: " + result
                } catch (err) {
                    status.text = "Failed: " + err
                }
            }
        }

        Label {
            id: status
            text: SanitizerBridge.status
            wrapMode: Text.Wrap
        }
    }

    FileDialog {
        id: fileDialog
        title: "Select SCL file"
        nameFilters: ["SCL files (*.scd *.ssd *.cid *.icd *.iid *.sed *.scl)"]
        onAccepted: {
            fileField.text = SanitizerBridge.url_to_local_file(selectedFile)
        }
    }
}