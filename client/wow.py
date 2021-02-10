
import sys
from PySide6.QtWidgets import (QLineEdit, QPushButton, QApplication,
    QVBoxLayout, QDialog)
import os
dirname = os.path.dirname(__file__)
class Form(QDialog):
    
    def __init__(self, parent=None):
        super(Form, self).__init__(parent)
        # Setting style sheet
        style_ = open(os.path.join(dirname, 'style.qss'), "r")
        self.setStyleSheet(style_)
        # Create widgets
        self.menuRequest = QPushButton("Get Menu From Server")
        self.send = QPushButton("Send Day End Report")
        # Create layout and add widgets
        layout = QVBoxLayout()
        layout.addWidget(self.edit)
        layout.addWidget(self.button)
        # Set dialog layout
        self.setLayout(layout)
        # Add button signal to greetings slot
        self.menuRequest.clicked.connect(self.greetings)

    # Greets the user
    def greetings(self):
        print(f"Hello {self.edit.text()}")

if __name__ == '__main__':
    # Create the Qt Application
    app = QApplication(sys.argv)
    # Create and show the form
    form = Form()
    form.show()
    # Run the main Qt loop
    sys.exit(app.exec_())