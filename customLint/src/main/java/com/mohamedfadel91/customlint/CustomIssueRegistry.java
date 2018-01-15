package com.mohamedfadel91.customlint;

import com.android.tools.lint.client.api.IssueRegistry;
import com.android.tools.lint.detector.api.Issue;

import java.util.Collections;
import java.util.List;

/**
 * Created by Fadel on 15/01/18.
 */

public class CustomIssueRegistry extends IssueRegistry {
    @Override
    public List<Issue> getIssues() {
        return Collections.singletonList(SecurePrefDetector.ISSUE);
    }
}
