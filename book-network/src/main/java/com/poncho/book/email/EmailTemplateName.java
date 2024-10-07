package com.poncho.book.email;

import lombok.Getter;

@Getter
public enum EmailTemplateName {
    ACTIVATE_ACCOUNT("activate_account");
    public final String name;
    private EmailTemplateName(String name) {
        this.name = name;
    }
}
