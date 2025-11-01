const nodemailer = require("nodemailer");

async function sendMail() {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "ishvarekh@gmail.com",      // तुम्हारा Gmail
        pass: "okfalnylrexzvhuy"          // App Password
      }
    });

    const info = await transporter.sendMail({
      from: '"Test Mail" <ishvarekh@gmail.com>',
      to: "ishvarekh@gmail.com",   // अभी test के लिए खुद को भेजो
      subject: "Hello ✔",
      text: "This is a test email from Node.js",
      html: "<b>This is a test email from Node.js</b>"
    });

    console.log("✅ Mail sent:", info.response);
  } catch (err) {
    console.error("❌ Error:", err);
  }
}

sendMail();
