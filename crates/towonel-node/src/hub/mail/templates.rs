use super::LinkBase;

pub struct RenderedMail {
    pub subject: String,
    pub text: String,
    pub html: String,
}

pub fn verification(link_base: &LinkBase, from_name: &str, token: &str) -> RenderedMail {
    let link = link_base.verify_url(token);
    RenderedMail {
        subject: format!("Verify your {from_name} email"),
        text: format!(
            "Confirm your email by opening this link (expires in 24 hours):\n\n\
             {link}\n\n\
             If you didn't sign up, ignore this email.\n",
        ),
        html: button_layout(
            from_name,
            "Confirm your email",
            "Open the link below to verify your email.",
            &link,
            "Verify email",
            "Link expires in 24 hours.",
        ),
    }
}

pub fn password_reset(link_base: &LinkBase, from_name: &str, token: &str) -> RenderedMail {
    let link = link_base.password_reset_url(token);
    RenderedMail {
        subject: format!("Reset your {from_name} password"),
        text: format!(
            "Open this link to set a new password (expires in 1 hour):\n\n\
             {link}\n\n\
             If this wasn't you, ignore this email.\n",
        ),
        html: button_layout(
            from_name,
            "Reset your password",
            "Open the link below to choose a new password.",
            &link,
            "Choose a new password",
            "Link expires in 1 hour.",
        ),
    }
}

pub fn signup_invite(link_base: &LinkBase, from_name: &str, code: &str) -> RenderedMail {
    let link = link_base.signup_invite_url(code);
    RenderedMail {
        subject: format!("Your {from_name} invite"),
        text: format!(
            "You're invited to create a {from_name} account.\n\n\
             {link}\n\n\
             Invite code: {code}\n",
        ),
        html: button_layout(
            from_name,
            "You're invited",
            "Use the link below to create your account.",
            &link,
            "Create account",
            &format!("Invite code: <code>{code}</code>"),
        ),
    }
}

fn button_layout(
    from_name: &str,
    heading: &str,
    intro: &str,
    link: &str,
    button_label: &str,
    footnote: &str,
) -> String {
    format!(
        "<!doctype html>\n\
         <html><body style=\"margin:0;padding:0;background:#f5f5f5;font-family:\
         -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111;\">\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\
         <tr><td align=\"center\" style=\"padding:32px 16px;\">\
         <table role=\"presentation\" width=\"480\" cellpadding=\"0\" cellspacing=\"0\" \
         style=\"max-width:480px;width:100%;background:#fff;border-radius:12px;\
         border:1px solid #e5e5e5;\">\
         <tr><td style=\"padding:28px 28px 4px;\">\
         <div style=\"font-size:13px;color:#666;letter-spacing:0.08em;text-transform:uppercase;\">{from_name}</div>\
         <h1 style=\"margin:8px 0 12px;font-size:20px;font-weight:600;\">{heading}</h1>\
         <p style=\"margin:0 0 24px;font-size:15px;line-height:1.5;color:#333;\">{intro}</p>\
         <p style=\"margin:0 0 24px;\"><a href=\"{link}\" \
         style=\"display:inline-block;padding:11px 18px;background:#111;color:#fff;\
         text-decoration:none;border-radius:8px;font-size:14px;font-weight:500;\">{button_label}</a></p>\
         <p style=\"margin:0 0 20px;font-size:12px;color:#666;word-break:break-all;\">\
         <a href=\"{link}\" style=\"color:#444;text-decoration:underline;\">{link}</a></p>\
         <p style=\"margin:0;font-size:12px;color:#888;\">{footnote}</p>\
         </td></tr></table></td></tr></table></body></html>",
    )
}
