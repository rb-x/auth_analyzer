package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;
import java.util.HashSet;
import java.util.Set;

public class UniquePathFilter extends RequestFilter {
    private final Set<String> seenPaths = new HashSet<>();
    
    public UniquePathFilter(int filterIndex, String description) {
        super(filterIndex, description);
    }

    @Override
    public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, 
                               IRequestInfo requestInfo, IResponseInfo responseInfo) {
        if (!onOffButton.isSelected()) {
            return false;
        }

        String path = requestInfo.getUrl().getPath();
        if (seenPaths.contains(path)) {
            incrementFiltered();
            return true;
        }
        
        seenPaths.add(path);
        return false;
    }

    @Override
    public boolean hasStringLiterals() {
        return false;
    }

    public void clearSeenPaths() {
        seenPaths.clear();
    }
} 